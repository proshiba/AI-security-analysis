"""VBScriptの定数数値配列から ``Execute`` へ至る限定形を静的復元する。

一般VBScript evaluatorではない。``Array`` の整数定数、整数剰余で導出した
単一byte差分、``For 0 To UBound``、``Chr`` 連結、直接 ``Execute`` が一意に
結び付く場合だけを扱う。COM、WMI、process、network、``Execute`` 自体は一切
呼び出さない。
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass

from unpackers import vbscript_constant_sink as vb

IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
PROFILE_NAME = "vbscript-constant-array-chr-direct-execute-v1"

_ARRAY_ASSIGN_RE = re.compile(
    rf"^({IDENTIFIER})\s*=\s*array\s*\((.*)\)$",
    re.IGNORECASE,
)
_FOR_RE = re.compile(
    rf"^for\s+({IDENTIFIER})\s*=\s*(.+?)\s+to\s+ubound\s*\(\s*"
    rf"({IDENTIFIER})\s*\)$",
    re.IGNORECASE,
)
_APPEND_RE = re.compile(
    rf"^({IDENTIFIER})\s*=\s*\1\s*(?:\+|&)\s*chrw?\s*\(\s*"
    rf"({IDENTIFIER})\s*\(\s*({IDENTIFIER})\s*\)\s*-\s*"
    rf"\(?\s*({IDENTIFIER})\s*\)?\s*\)$",
    re.IGNORECASE,
)
_NEXT_RE = re.compile(rf"^next(?:\s+({IDENTIFIER}))?$", re.IGNORECASE)
_MOD_RE = re.compile(
    rf"^({IDENTIFIER})\s+mod\s+({IDENTIFIER})$",
    re.IGNORECASE,
)
_EMPTY_ASSIGN_RE = re.compile(rf'^({IDENTIFIER})\s*=\s*""$', re.IGNORECASE)
_CREATEOBJECT_RUN_RE = re.compile(
    r'^createobject\s*\(\s*"((?:""|[^"])*)"\s*\)\s*\.\s*run\s+'
    r'"((?:""|[^"])*)"\s*,\s*(.+?)(?:\s*,\s*(true|false))?$',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class VbscriptArrayChrLimits:
    """限定復元に用いるhard limit。"""

    max_input_bytes: int = 2 * 1024 * 1024
    max_statements: int = 50_000
    max_array_items: int = 262_144
    max_array_characters: int = 4 * 1024 * 1024
    max_output_bytes: int = 2 * 1024 * 1024
    max_work_units: int = 8 * 1024 * 1024
    max_integer_absolute: int = 16 * 1024 * 1024


DEFAULT_LIMITS = VbscriptArrayChrLimits()


def _safety() -> dict[str, bool]:
    return {
        "sample_executed": False,
        "network_contacted": False,
        "general_vbscript_interpreter_used": False,
        "eval_execute_invoked": False,
        "com_created": False,
        "powershell_started": False,
        "process_started": False,
        "raw_source_included": False,
        "raw_array_included": False,
        "recovered_output_in_report": False,
    }


def _base_report(
    limits: VbscriptArrayChrLimits,
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
        "safety": _safety(),
    }


def _assignment_map(
    statements: list[vb._Statement],
) -> dict[str, list[tuple[vb._Statement, str]]]:
    values: dict[str, list[tuple[vb._Statement, str]]] = {}
    for statement in statements:
        assignment = vb._ASSIGNMENT_RE.fullmatch(statement.text)
        if assignment is None:
            continue
        values.setdefault(assignment.group(1).casefold(), []).append(
            (statement, assignment.group(2).strip())
        )
    return values


def _single_constant(
    assignments: dict[str, list[tuple[vb._Statement, str]]],
    name: str,
    *,
    maximum: int,
) -> int | None:
    matches = assignments.get(name.casefold(), [])
    if len(matches) != 1:
        return None
    return vb._constant_integer(matches[0][1], maximum)


def _resolve_key(
    assignments: dict[str, list[tuple[vb._Statement, str]]],
    name: str,
    *,
    maximum: int,
) -> tuple[int, str] | None:
    matches = assignments.get(name.casefold(), [])
    if len(matches) != 1:
        return None
    direct = vb._constant_integer(matches[0][1], maximum)
    if direct is not None:
        return direct, "constant_integer_v1"
    modulo = _MOD_RE.fullmatch(matches[0][1])
    if modulo is None:
        return None
    left = _single_constant(assignments, modulo.group(1), maximum=maximum)
    right = _single_constant(assignments, modulo.group(2), maximum=maximum)
    if left is None or right is None or right == 0:
        return None
    return left % right, "constant_integer_modulo_v1"


def _parse_array(
    expression: str,
    *,
    limits: VbscriptArrayChrLimits,
) -> list[int] | None:
    if len(expression) > limits.max_array_characters:
        raise vb._LimitExceeded("max_array_characters")
    terms = [item.strip() for item in expression.split(",")]
    if not terms or any(not item for item in terms):
        return None
    if len(terms) > limits.max_array_items:
        raise vb._LimitExceeded("max_array_items")
    values: list[int] = []
    for term in terms:
        value = vb._constant_integer(term, limits.max_integer_absolute)
        if value is None:
            return None
        values.append(value)
    return values


def _validate_recovered_script(
    value: str,
    *,
    budget: vb._Budget,
    maximum_integer: int,
) -> tuple[bool, dict[str, object]]:
    """既存token streamか、厳密な ``WScript.Shell.Run`` 1文だけを受理する。"""

    valid, report = vb._validate_output(value, budget=budget)
    if valid:
        return valid, report
    match = _CREATEOBJECT_RUN_RE.fullmatch(value.strip())
    if match is None:
        return False, {}
    progid = match.group(1).replace('""', '"')
    command = match.group(2).replace('""', '"')
    window_style = vb._constant_integer(match.group(3), maximum_integer)
    if (
        progid.casefold() != "wscript.shell"
        or window_style is None
        or not -10 <= window_style <= 10
        or len(command) < 8
        or "\x00" in command
        or not all(
            character.isprintable() or character in "\r\n\t" for character in command
        )
    ):
        return False, {}
    budget.work(len(command))
    return (
        True,
        {
            "format": "bounded_vbscript_wscript_shell_run",
            "statement_count": 1,
            "command_character_count": len(command),
            "wait_argument_present": match.group(4) is not None,
        },
    )


def recover_vbscript_array_chr(
    data: bytes,
    *,
    limits: VbscriptArrayChrLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """一意な ``Array`` → ``Chr`` → ``Execute`` profileを非実行で復元する。"""

    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    if len(data) > limits.max_input_bytes:
        return _base_report(limits, status="input_limit_exceeded"), []
    decoded = vb._decode_source(data)
    if decoded is None:
        return _base_report(limits, status="text_decode_failed"), []
    text, encoding = decoded
    parse_limits = vb.VbscriptConstantSinkLimits(
        max_input_bytes=limits.max_input_bytes,
        max_statements=limits.max_statements,
        max_work_units=limits.max_work_units,
        max_integer_absolute=limits.max_integer_absolute,
    )
    budget = vb._Budget(parse_limits)
    rejections: Counter[str] = Counter()
    try:
        statements = vb._scan_statements(text, limits=parse_limits, budget=budget)
        partitioned = vb._partition_procedures(statements, limits=parse_limits)
        if partitioned is None:
            report = _base_report(limits, status="ambiguous_procedure_structure")
            report.update({"encoding": encoding, "candidate_set_complete": False})
            return report, []
        top_level, procedures = partitioned
        assignments = _assignment_map(top_level)
        array_matches: list[tuple[int, re.Match[str]]] = []
        for index, statement in enumerate(top_level):
            match = _ARRAY_ASSIGN_RE.fullmatch(statement.text)
            if match is not None:
                array_matches.append((index, match))
        sink_matches: list[tuple[int, str]] = []
        for index, statement in enumerate(top_level):
            match = vb._DIRECT_EXECUTE_RE.fullmatch(statement.text)
            if match is not None:
                sink_matches.append((index, match.group(1) or match.group(2)))
        candidates: list[dict[str, object]] = []
        artifacts: list[tuple[str, bytes]] = []
        seen: set[str] = set()
        work_units = budget.work_units
        for array_index, array_match in array_matches:
            array_name = array_match.group(1)
            if len(assignments.get(array_name.casefold(), [])) != 1:
                rejections["ambiguous_array_assignment"] += 1
                continue
            values = _parse_array(array_match.group(2), limits=limits)
            if values is None:
                rejections["nonconstant_array"] += 1
                continue
            work_units += len(array_match.group(2)) + len(values)
            if work_units > limits.max_work_units:
                raise vb._LimitExceeded("max_work_units")
            for for_index, statement in enumerate(top_level):
                loop = _FOR_RE.fullmatch(statement.text)
                if loop is None or loop.group(3).casefold() != array_name.casefold():
                    continue
                start = vb._constant_integer(loop.group(2), limits.max_integer_absolute)
                if start != 0:
                    rejections["unsupported_loop_start"] += 1
                    continue
                index_name = loop.group(1)
                next_matches = [
                    (idx, _NEXT_RE.fullmatch(candidate.text))
                    for idx, candidate in enumerate(
                        top_level[for_index + 1 :], for_index + 1
                    )
                    if _NEXT_RE.fullmatch(candidate.text) is not None
                ]
                if not next_matches:
                    rejections["next_not_found"] += 1
                    continue
                next_index, next_match = next_matches[0]
                if next_match is None or (
                    next_match.group(1) is not None
                    and next_match.group(1).casefold() != index_name.casefold()
                ):
                    rejections["loop_index_mismatch"] += 1
                    continue
                appends = []
                for append_index in range(for_index + 1, next_index):
                    append = _APPEND_RE.fullmatch(top_level[append_index].text)
                    if append is not None:
                        appends.append((append_index, append))
                if len(appends) != 1:
                    rejections["ambiguous_chr_append"] += 1
                    continue
                append_index, append = appends[0]
                if (
                    append.group(2).casefold() != array_name.casefold()
                    or append.group(3).casefold() != index_name.casefold()
                ):
                    rejections["append_state_mismatch"] += 1
                    continue
                output_name = append.group(1)
                output_assignments = assignments.get(output_name.casefold(), [])
                initializers = [
                    item
                    for item in output_assignments
                    if _EMPTY_ASSIGN_RE.fullmatch(item[0].text) is not None
                ]
                if len(output_assignments) != 2 or len(initializers) != 1:
                    rejections["ambiguous_output_state"] += 1
                    continue
                init_index = top_level.index(initializers[0][0])
                key = _resolve_key(
                    assignments,
                    append.group(4),
                    maximum=limits.max_integer_absolute,
                )
                if key is None:
                    rejections["unresolved_constant_key"] += 1
                    continue
                key_value, key_resolution = key
                related_sinks = [
                    index
                    for index, name in sink_matches
                    if name.casefold() == output_name.casefold()
                ]
                if len(related_sinks) != 1:
                    rejections["ambiguous_direct_sink"] += 1
                    continue
                sink_index = related_sinks[0]
                if (
                    not array_index
                    < init_index
                    < for_index
                    < append_index
                    < next_index
                    < sink_index
                ):
                    rejections["invalid_profile_order"] += 1
                    continue
                decoded_values = [value - key_value for value in values]
                if any(value < 0 or value > 0xFF for value in decoded_values):
                    rejections["decoded_byte_out_of_range"] += 1
                    continue
                output = bytes(decoded_values)
                work_units += len(output)
                if work_units > limits.max_work_units:
                    raise vb._LimitExceeded("max_work_units")
                if (
                    not output
                    or len(output) > limits.max_output_bytes
                    or b"\x00" in output
                ):
                    rejections["invalid_output_size_or_nul"] += 1
                    continue
                try:
                    output_text = output.decode("ascii")
                except UnicodeDecodeError:
                    rejections["non_ascii_output"] += 1
                    continue
                valid, validation = _validate_recovered_script(
                    output_text,
                    budget=budget,
                    maximum_integer=limits.max_integer_absolute,
                )
                if not valid:
                    rejections["output_format_rejected"] += 1
                    continue
                digest = hashlib.sha256(output).hexdigest()
                if digest in seen:
                    rejections["duplicate_output"] += 1
                    continue
                seen.add(digest)
                command_output: bytes | None = None
                run_match = _CREATEOBJECT_RUN_RE.fullmatch(output_text.strip())
                if run_match is not None:
                    command_output = (
                        run_match.group(2).replace('""', '"').encode("ascii")
                    )
                candidates.append(
                    {
                        "array_line": top_level[array_index].line,
                        "loop_line": statement.line,
                        "sink_line": top_level[sink_index].line,
                        "array_item_count": len(values),
                        "key_resolution": key_resolution,
                        "output_size": len(output),
                        "output_sha256": digest,
                        "output_validation": validation,
                        "derived_command": (
                            {
                                "size": len(command_output),
                                "sha256": hashlib.sha256(command_output).hexdigest(),
                            }
                            if command_output is not None
                            else None
                        ),
                    }
                )
                artifacts.append(("vbscript-array-chr-direct-execute", output))
                if command_output is not None:
                    artifacts.append(
                        ("vbscript-wscript-shell-run-command.cmd", command_output)
                    )
    except vb._LexicalRejected as error:
        report = _base_report(limits, status="ambiguous_lexical_structure")
        report.update(
            {
                "encoding": encoding,
                "lexical_rejection": str(error),
                "candidate_set_complete": False,
                "rejections": dict(sorted(rejections.items())),
            }
        )
        return report, []
    except vb._LimitExceeded as error:
        report = _base_report(limits, status="limit_exceeded")
        report.update(
            {
                "encoding": encoding,
                "limit": error.limit_name,
                "candidate_set_complete": False,
                "candidate_set_truncated": True,
                "rejections": dict(sorted(rejections.items())),
            }
        )
        return report, []

    status = "artifacts_recovered" if artifacts else "pattern_not_found"
    if not artifacts and rejections:
        status = "candidates_rejected"
    report = _base_report(limits, status=status)
    report.update(
        {
            "encoding": encoding,
            "statement_count": len(statements),
            "procedure_count": len(procedures),
            "array_candidate_count": len(array_matches),
            "direct_sink_count": len(sink_matches),
            "work_units": work_units,
            "candidate_count": len(candidates),
            "candidate_set_complete": True,
            "candidates": candidates,
            "rejections": dict(sorted(rejections.items())),
            "evaluation_boundary": {
                "operations_used": [
                    "constant_integer_array",
                    "constant_integer_modulo",
                    "bounded_byte_subtraction",
                    "direct_execute_dataflow",
                ],
                "general_expression_evaluation": False,
                "dynamic_call_evaluation": False,
            },
        }
    )
    return report, artifacts
