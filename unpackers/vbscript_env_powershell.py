"""VBScriptの環境変数経由PowerShell stdin loaderを非実行で復元する。

一般VBScript evaluatorではない。固定slice関数で復元した定数を使い、
``WScript.Shell.Environment("Process")`` にliteral self-append bufferと
``powershell.exe`` launcherを格納し、固定 ``cmd.exe`` pipe templateから
``WScript.Shell.Run`` へ至る一意なdataflowだけを扱う。COM、process、
PowerShell、``Execute`` は一切呼び出さない。
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass

from unpackers import vbscript_constant_sink as vb

IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
PROFILE_NAME = "vbscript-process-env-powershell-stdin-v1"

_CREATEOBJECT_RE = re.compile(
    r'^createobject\s*\(\s*"((?:""|[^"])*)"\s*\)$',
    re.IGNORECASE,
)
_ENVIRONMENT_SET_RE = re.compile(
    rf"^({IDENTIFIER})\.environment\s*\(\s*({IDENTIFIER})\s*\)"
    rf"\.item\s*\(\s*({IDENTIFIER})\s*\)\s*=\s*(.+)$",
    re.IGNORECASE,
)
_QUOTED_IDENTIFIER_RE = re.compile(
    rf"^chr\s*\(\s*34\s*\)\s*\+\s*({IDENTIFIER})\s*\+\s*"
    r"chr\s*\(\s*34\s*\)$",
    re.IGNORECASE,
)
_RUN_PREFIX_RE = re.compile(
    rf"^({IDENTIFIER})\s*=\s*({IDENTIFIER})\.run\s*\(\s*"
    rf"({IDENTIFIER})\s*,\s*(.+)$",
    re.IGNORECASE,
)
_COMPOUND_EXECUTE_MID_RE = re.compile(
    rf"^execute\s+({IDENTIFIER})\s*\+\s*mid\s*\(\s*({IDENTIFIER})\s*,"
    r"\s*(.+?)\s*,\s*(.+?)\s*\)$",
    re.IGNORECASE,
)
_CMD_STDIN_TEMPLATE_RE = re.compile(
    rf"^cmd\.exe\s+/v:on\s+/c\s+echo\s+\^%({IDENTIFIER})\^%\s*"
    rf"\|\s*!({IDENTIFIER})!\s+-$",
    re.IGNORECASE,
)
_DO_UNTIL_NOW_RE = re.compile(
    rf"^do\s+until\s+\(?\s*now\s*\(\s*\)\s*>\s*({IDENTIFIER})\s*\)?$",
    re.IGNORECASE,
)
_DATEADD_NOW_RE = re.compile(
    r'^dateadd\s*\(\s*"((?:""|[^"])*)"\s*,\s*(.+?)\s*,\s*'
    r"now\s*\(\s*\)\s*\)$",
    re.IGNORECASE,
)
_IGNORABLE_LOOP_DECOY_RE = re.compile(r"^command$", re.IGNORECASE)
_POWERSHELL_PATH_RE = re.compile(
    r"^[A-Za-z]:\\windows\\(?:syswow64|system32)\\windowspowershell"
    r"\\v1\.0\\powershell\.exe$",
    re.IGNORECASE,
)
_ENVIRONMENT_NAME_RE = re.compile(rf"^{IDENTIFIER}$", re.IGNORECASE)


@dataclass(frozen=True)
class VbscriptEnvPowershellLimits:
    """限定dataflow復元に用いるhard limit。"""

    max_input_bytes: int = 2 * 1024 * 1024
    max_statements: int = 50_000
    max_functions: int = 256
    max_decoded_assignments: int = 2048
    max_decoded_value_characters: int = 16 * 1024
    max_literal_chunks: int = 4096
    max_output_bytes: int = 2 * 1024 * 1024
    max_candidate_count: int = 32
    max_work_units: int = 8 * 1024 * 1024
    max_integer_absolute: int = 16 * 1024 * 1024


DEFAULT_LIMITS = VbscriptEnvPowershellLimits()


@dataclass(frozen=True)
class _DecodedAssignment:
    target: str
    line: int
    value: str


@dataclass(frozen=True)
class _LiteralBuffer:
    name: str
    first_line: int
    last_line: int
    chunk_count: int
    value: str


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
        "raw_decoded_constants_in_report": False,
        "raw_payload_in_report": False,
    }


def _base_report(
    limits: VbscriptEnvPowershellLimits,
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
) -> dict[str, list[vb._Statement]]:
    values: dict[str, list[vb._Statement]] = {}
    for statement in statements:
        assignment = vb._ASSIGNMENT_RE.fullmatch(statement.text)
        if assignment is not None:
            values.setdefault(assignment.group(1).casefold(), []).append(statement)
    return values


def _decode_constant_assignments(
    statements: list[vb._Statement],
    procedures: list[vb._Procedure],
    *,
    parse_limits: vb.VbscriptConstantSinkLimits,
    limits: VbscriptEnvPowershellLimits,
    budget: vb._Budget,
) -> tuple[dict[str, list[_DecodedAssignment]], Counter[str]]:
    rejections: Counter[str] = Counter()
    external = vb._resolve_repeated_character_integer_constants(
        statements,
        limits=parse_limits,
    )
    functions: dict[str, list[vb._Procedure]] = {}
    for procedure in procedures:
        if procedure.kind == "function":
            functions.setdefault(procedure.name.casefold(), []).append(procedure)
    profiles: dict[str, tuple[vb._SliceProfile | None, str | None]] = {}
    decoded: dict[str, list[_DecodedAssignment]] = {}
    decoded_count = 0
    for statement in statements:
        assignment = vb._ASSIGNMENT_RE.fullmatch(statement.text)
        if assignment is None:
            continue
        call = vb._CALL_LITERAL_RE.fullmatch(assignment.group(2).strip())
        if call is None:
            continue
        function_key = call.group(1).casefold()
        definitions = functions.get(function_key, [])
        if len(definitions) != 1:
            continue
        if function_key not in profiles:
            profiles[function_key] = vb._match_slice_profile(
                definitions[0],
                limits=parse_limits,
                budget=budget,
                external_integer_constants=external,
            )
        profile, rejection = profiles[function_key]
        if profile is None:
            rejections[rejection or "decoder_profile_rejected"] += 1
            continue
        value = vb._recover_slice(
            vb._decode_vb_string(call.group(2)),
            profile,
            limits=parse_limits,
            budget=budget,
        )
        if value is None or "\x00" in value:
            rejections["decoded_value_invalid"] += 1
            continue
        if len(value) > limits.max_decoded_value_characters:
            raise vb._LimitExceeded("max_decoded_value_characters")
        if not all(
            character.isprintable() or character in "\r\n\t" for character in value
        ):
            rejections["decoded_value_nonprintable"] += 1
            continue
        decoded_count += 1
        if decoded_count > limits.max_decoded_assignments:
            raise vb._LimitExceeded("max_decoded_assignments")
        target = assignment.group(1)
        decoded.setdefault(target.casefold(), []).append(
            _DecodedAssignment(target=target, line=statement.line, value=value)
        )
    return decoded, rejections


def _single_decoded(
    values: dict[str, list[_DecodedAssignment]],
    name: str,
    *,
    assignments: dict[str, list[vb._Statement]] | None = None,
) -> _DecodedAssignment | None:
    if assignments is not None and len(assignments.get(name.casefold(), [])) != 1:
        return None
    matches = values.get(name.casefold(), [])
    return matches[0] if len(matches) == 1 else None


def _literal_buffers(
    statements: list[vb._Statement],
    assignments: dict[str, list[vb._Statement]],
    *,
    limits: VbscriptEnvPowershellLimits,
    budget: vb._Budget,
) -> dict[str, _LiteralBuffer]:
    chunks: dict[str, list[tuple[int, str]]] = {}
    for statement in statements:
        match = vb._REPEATED_CHARACTER_APPEND_RE.fullmatch(statement.text)
        if match is None:
            continue
        value = vb._decode_vb_string(match.group(2))
        chunks.setdefault(match.group(1).casefold(), []).append((statement.line, value))
    buffers: dict[str, _LiteralBuffer] = {}
    for name, items in chunks.items():
        if len(items) > limits.max_literal_chunks:
            raise vb._LimitExceeded("max_literal_chunks")
        # payload stateに別形状の代入が混在する場合はfail closedとする。
        if len(assignments.get(name, [])) != len(items):
            continue
        total = sum(len(value) for _, value in items)
        if total > limits.max_output_bytes:
            raise vb._LimitExceeded("max_output_bytes")
        budget.work(total)
        value = "".join(chunk for _, chunk in items)
        buffers[name] = _LiteralBuffer(
            name=name,
            first_line=items[0][0],
            last_line=items[-1][0],
            chunk_count=len(items),
            value=value,
        )
    return buffers


def _shell_objects(
    statements: list[vb._Statement],
) -> dict[str, int]:
    values: dict[str, list[int]] = {}
    assignment_counts: Counter[str] = Counter()
    for statement in statements:
        assignment = vb._ASSIGNMENT_RE.fullmatch(statement.text)
        if assignment is None:
            continue
        assignment_counts[assignment.group(1).casefold()] += 1
        create = _CREATEOBJECT_RE.fullmatch(assignment.group(2).strip())
        if (
            create is None
            or vb._decode_vb_string(create.group(1)).casefold() != "wscript.shell"
        ):
            continue
        values.setdefault(assignment.group(1).casefold(), []).append(statement.line)
    return {
        name: lines[0]
        for name, lines in values.items()
        if len(lines) == 1 and assignment_counts[name] == 1
    }


def _direct_execute_lines(
    statements: list[vb._Statement],
) -> dict[str, list[int]]:
    values: dict[str, list[int]] = {}
    for statement in statements:
        match = vb._DIRECT_EXECUTE_RE.fullmatch(statement.text)
        if match is not None:
            values.setdefault((match.group(1) or match.group(2)).casefold(), []).append(
                statement.line
            )
    return values


def _resolve_closing_suffix(
    statements: list[vb._Statement],
    assignments: dict[str, list[vb._Statement]],
    *,
    source_name: str,
    start_expression: str,
    width_expression: str,
    maximum_integer: int,
) -> tuple[str, dict[str, object]] | None:
    start = vb._constant_integer(start_expression, maximum_integer)
    width = vb._constant_integer(width_expression, maximum_integer)
    if start is None or start < 1 or width != 1:
        return None
    source_key = source_name.casefold()
    source_assignments = assignments.get(source_key, [])
    if len(source_assignments) != 1:
        return None
    append_statement = source_assignments[0]
    append = vb._REPEATED_CHARACTER_APPEND_RE.fullmatch(append_statement.text)
    if append is None:
        return None
    character = vb._decode_vb_string(append.group(2))
    if character != ")":
        return None
    append_index = statements.index(append_statement)
    if append_index < 2 or append_index + 1 >= len(statements):
        return None
    loop_start = _DO_UNTIL_NOW_RE.fullmatch(statements[append_index - 1].text)
    if loop_start is None or statements[append_index + 1].text.casefold() != "loop":
        return None
    deadline_matches = assignments.get(loop_start.group(1).casefold(), [])
    if len(deadline_matches) != 1:
        return None
    deadline_statement = deadline_matches[0]
    deadline_index = statements.index(deadline_statement)
    loop_index = append_index - 1
    if not 0 <= deadline_index < loop_index or loop_index - deadline_index > 16:
        return None
    for decoy in statements[deadline_index + 1 : loop_index]:
        assignment = vb._ASSIGNMENT_RE.fullmatch(decoy.text)
        if assignment is None or assignment.group(1).casefold() in {
            source_key,
            loop_start.group(1).casefold(),
        }:
            return None
        expression = assignment.group(2).strip()
        if _IGNORABLE_LOOP_DECOY_RE.fullmatch(
            expression
        ) is None and not vb._is_ignored_constant_assignment(
            decoy.text,
            maximum=maximum_integer,
        ):
            return None
    deadline_assignment = vb._ASSIGNMENT_RE.fullmatch(deadline_statement.text)
    if (
        deadline_assignment is None
        or deadline_assignment.group(1).casefold() != loop_start.group(1).casefold()
    ):
        return None
    dateadd = _DATEADD_NOW_RE.fullmatch(deadline_assignment.group(2).strip())
    if dateadd is None:
        return None
    interval = vb._decode_vb_string(dateadd.group(1)).casefold()
    duration = vb._constant_integer(dateadd.group(2), maximum_integer)
    if interval not in {"s", "n", "h", "d"} or duration is None or duration <= 0:
        return None
    return (
        character,
        {
            "method": "positive_time_repeated_character_intent_v1",
            "requested_index": start,
            "width": width,
            "interval_unit": interval,
            "duration": duration,
            "append_line": append_statement.line,
        },
    )


def _payload_bytes(value: str, *, maximum: int) -> bytes | None:
    if not 256 <= len(value) <= maximum or "\x00" in value:
        return None
    if not all(ord(character) <= 0x7F for character in value):
        return None
    if not all(character.isprintable() or character in "\r\n\t" for character in value):
        return None
    # full dataflowがPowerShell stdinを証明するが、空白同然のbufferは公開しない。
    if len(value.strip()) < 128 or "$" not in value:
        return None
    return value.encode("ascii")


def recover_vbscript_env_powershell(
    data: bytes,
    *,
    limits: VbscriptEnvPowershellLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """厳格なProcess環境変数→PowerShell stdin dataflowだけを復元する。"""

    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    if len(data) > limits.max_input_bytes:
        return _base_report(limits, status="input_limit_exceeded"), []
    decoded_source = vb._decode_source(data)
    if decoded_source is None:
        return _base_report(limits, status="text_decode_failed"), []
    text, encoding = decoded_source
    parse_limits = vb.VbscriptConstantSinkLimits(
        max_input_bytes=limits.max_input_bytes,
        max_statements=limits.max_statements,
        max_functions=limits.max_functions,
        max_candidate_count=limits.max_candidate_count,
        max_output_bytes=limits.max_output_bytes,
        max_work_units=limits.max_work_units,
        max_integer_absolute=limits.max_integer_absolute,
    )
    budget = vb._Budget(parse_limits)
    rejections: Counter[str] = Counter()
    compound_candidate_count = 0
    try:
        statements = vb._scan_statements(text, limits=parse_limits, budget=budget)
        partitioned = vb._partition_procedures(statements, limits=parse_limits)
        if partitioned is None:
            report = _base_report(limits, status="ambiguous_procedure_structure")
            report.update({"encoding": encoding, "candidate_set_complete": False})
            return report, []
        top_level, procedures = partitioned
        assignments = _assignment_map(top_level)
        decoded, decode_rejections = _decode_constant_assignments(
            top_level,
            procedures,
            parse_limits=parse_limits,
            limits=limits,
            budget=budget,
        )
        rejections.update(decode_rejections)
        buffers = _literal_buffers(
            top_level,
            assignments,
            limits=limits,
            budget=budget,
        )
        shell_objects = _shell_objects(top_level)
        direct_executes = _direct_execute_lines(top_level)

        environment_sets: list[dict[str, object]] = []
        for records in decoded.values():
            if len(records) != 1:
                continue
            record = records[0]
            sink_lines = direct_executes.get(record.target.casefold(), [])
            if len(sink_lines) != 1 or sink_lines[0] <= record.line:
                continue
            match = _ENVIRONMENT_SET_RE.fullmatch(record.value.strip())
            if match is None:
                continue
            scope = _single_decoded(
                decoded,
                match.group(2),
                assignments=assignments,
            )
            name_value = _single_decoded(
                decoded,
                match.group(3),
                assignments=assignments,
            )
            if (
                scope is None
                or scope.value.casefold() != "process"
                or name_value is None
                or _ENVIRONMENT_NAME_RE.fullmatch(name_value.value) is None
                or scope.line >= sink_lines[0]
                or name_value.line >= sink_lines[0]
            ):
                rejections["environment_metadata_unresolved"] += 1
                continue
            environment_sets.append(
                {
                    "shell": match.group(1),
                    "name": name_value.value,
                    "value_expression": match.group(4).strip(),
                    "decoded_line": record.line,
                    "execute_line": sink_lines[0],
                }
            )

        candidates: list[dict[str, object]] = []
        artifacts: list[tuple[str, bytes]] = []
        seen: set[str] = set()
        for statement in top_level:
            compound = _COMPOUND_EXECUTE_MID_RE.fullmatch(statement.text)
            if compound is None:
                continue
            compound_candidate_count += 1
            run_record = _single_decoded(
                decoded,
                compound.group(1),
                assignments=assignments,
            )
            if run_record is None or run_record.line >= statement.line:
                rejections["run_prefix_unresolved"] += 1
                continue
            run = _RUN_PREFIX_RE.fullmatch(run_record.value.strip())
            if run is None:
                rejections["run_prefix_shape_rejected"] += 1
                continue
            window_style = vb._constant_integer(
                run.group(4), limits.max_integer_absolute
            )
            if window_style != 0:
                rejections["run_window_style_rejected"] += 1
                continue
            shell_name = run.group(2)
            shell_line = shell_objects.get(shell_name.casefold())
            if shell_line is None or shell_line >= statement.line:
                rejections["wscript_shell_unresolved"] += 1
                continue
            command = _single_decoded(
                decoded,
                run.group(3),
                assignments=assignments,
            )
            if command is None or command.line >= statement.line:
                rejections["command_template_unresolved"] += 1
                continue
            command_match = _CMD_STDIN_TEMPLATE_RE.fullmatch(command.value.strip())
            if command_match is None:
                rejections["command_template_rejected"] += 1
                continue
            suffix = _resolve_closing_suffix(
                top_level,
                assignments,
                source_name=compound.group(2),
                start_expression=compound.group(3),
                width_expression=compound.group(4),
                maximum_integer=limits.max_integer_absolute,
            )
            if suffix is None or not (run_record.value + suffix[0]).endswith(")"):
                rejections["compound_execute_suffix_unresolved"] += 1
                continue

            payload_setters = []
            launcher_setters = []
            for environment_set in environment_sets:
                if str(environment_set["shell"]).casefold() != shell_name.casefold():
                    continue
                expression = str(environment_set["value_expression"])
                if vb._IDENTIFIER_RE.fullmatch(expression):
                    buffer = buffers.get(expression.casefold())
                    if buffer is not None:
                        payload_setters.append((environment_set, buffer))
                    continue
                quoted = _QUOTED_IDENTIFIER_RE.fullmatch(expression)
                if quoted is None:
                    continue
                path = _single_decoded(
                    decoded,
                    quoted.group(1),
                    assignments=assignments,
                )
                if path is not None and _POWERSHELL_PATH_RE.fullmatch(path.value):
                    launcher_setters.append((environment_set, path))
            if len(payload_setters) != 1 or len(launcher_setters) != 1:
                rejections["environment_setter_pair_ambiguous"] += 1
                continue
            payload_setter, buffer = payload_setters[0]
            launcher_setter, launcher_path = launcher_setters[0]
            if (
                str(payload_setter["name"]).casefold()
                != command_match.group(1).casefold()
                or str(launcher_setter["name"]).casefold()
                != command_match.group(2).casefold()
                or buffer.last_line >= int(payload_setter["execute_line"])
                or launcher_path.line >= int(launcher_setter["execute_line"])
                or shell_line >= int(payload_setter["execute_line"])
                or shell_line >= int(launcher_setter["execute_line"])
                or int(payload_setter["execute_line"]) >= statement.line
                or int(launcher_setter["execute_line"]) >= statement.line
            ):
                rejections["environment_command_dataflow_mismatch"] += 1
                continue
            output = _payload_bytes(buffer.value, maximum=limits.max_output_bytes)
            if output is None:
                rejections["powershell_payload_validation_rejected"] += 1
                continue
            digest = hashlib.sha256(output).hexdigest()
            if digest in seen:
                rejections["duplicate_payload"] += 1
                continue
            if len(candidates) >= limits.max_candidate_count:
                raise vb._LimitExceeded("max_candidate_count")
            seen.add(digest)
            candidates.append(
                {
                    "compound_execute_line": statement.line,
                    "payload_buffer": {
                        "first_line": buffer.first_line,
                        "last_line": buffer.last_line,
                        "chunk_count": buffer.chunk_count,
                        "output_size": len(output),
                        "output_sha256": digest,
                    },
                    "process_environment": {
                        "payload_name_sha256": hashlib.sha256(
                            str(payload_setter["name"]).encode("ascii")
                        ).hexdigest(),
                        "launcher_name_sha256": hashlib.sha256(
                            str(launcher_setter["name"]).encode("ascii")
                        ).hexdigest(),
                        "raw_names_in_report": False,
                    },
                    "launcher": {
                        "kind": "canonical_windows_powershell_v1",
                        "path_sha256": hashlib.sha256(
                            launcher_path.value.casefold().encode("ascii")
                        ).hexdigest(),
                        "raw_path_in_report": False,
                    },
                    "command_template": "cmd_von_echo_process_env_pipe_launcher_stdin_v1",
                    "window_style": window_style,
                    "closing_suffix": suffix[1],
                }
            )
            artifacts.append(
                (f"vbscript-env-powershell-{len(artifacts) + 1:03d}.ps1", output)
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
    if (
        not artifacts
        and rejections
        and (compound_candidate_count > 0 or environment_sets)
    ):
        status = "candidates_rejected"
    report = _base_report(limits, status=status)
    report.update(
        {
            "encoding": encoding,
            "statement_count": len(statements),
            "procedure_count": len(procedures),
            "decoded_assignment_count": sum(len(items) for items in decoded.values()),
            "literal_buffer_count": len(buffers),
            "environment_setter_count": len(environment_sets),
            "compound_execute_candidate_count": compound_candidate_count,
            "candidate_count": len(candidates),
            "candidate_set_complete": True,
            "work_units": budget.work_units,
            "candidates": candidates,
            "rejections": dict(sorted(rejections.items())),
            "evaluation_boundary": {
                "operations_used": [
                    "fixed_inverse_slice",
                    "literal_self_append",
                    "process_environment_dataflow",
                    "constant_cmd_stdin_template",
                    "positive_time_repeated_character_suffix_intent",
                ],
                "general_expression_evaluation": False,
                "dynamic_call_evaluation": False,
                "execute_invoked": False,
                "process_environment_modified": False,
            },
        }
    )
    return report, artifacts
