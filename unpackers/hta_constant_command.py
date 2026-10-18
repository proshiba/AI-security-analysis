"""HTA内の定数VBScriptから ``WScript.Shell.Run`` 引数を静的復元する。

一般VBScript evaluatorではない。明示的なVBScript ``script`` block、定数文字列、
ASCII範囲の ``Chr`` / ``ChrW``、文字列連結、単一代入、同一receiverの
``ExpandEnvironmentStrings("%COMSPEC%")`` と ``Run`` だけを扱う。COM objectや
command、PowerShell、script自体は一切実行しない。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
PROFILE_NAME = "hta-vbscript-constant-wscript-shell-run-v1"

_SCRIPT_RE = re.compile(
    r"(?is)<script\b(?P<attrs>[^<>]{0,4096})>(?P<body>.*?)</script\s*>",
)
_ATTRIBUTE_RE = re.compile(
    r"(?is)([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*(\"(?:\"\"|[^\"])*\"|'[^']*')"
)
_DIM_RE = re.compile(r"^dim\s+(.+)$", re.IGNORECASE)
_ASSIGN_RE = re.compile(rf"^({IDENTIFIER})\s*=\s*(.+)$", re.IGNORECASE)
_SET_CREATEOBJECT_RE = re.compile(
    rf"^set\s+({IDENTIFIER})\s*=\s*createobject\s*\((.*)\)$",
    re.IGNORECASE,
)
_SET_NOTHING_RE = re.compile(
    rf"^set\s+({IDENTIFIER})\s*=\s*nothing$",
    re.IGNORECASE,
)
_RUN_RE = re.compile(
    rf"^({IDENTIFIER})\s*\.\s*run\s+(.+)$",
    re.IGNORECASE,
)
_CLOSE_RE = re.compile(r"^(?:self|window)\s*\.\s*close\s*$", re.IGNORECASE)
_CHR_RE = re.compile(r"^chr(w)?\s*\(\s*(.+?)\s*\)$", re.IGNORECASE)
_EXPAND_ENV_RE = re.compile(
    rf"^({IDENTIFIER})\s*\.\s*expandenvironmentstrings\s*\((.*)\)$",
    re.IGNORECASE,
)
_INTEGER_RE = re.compile(r"^[+-]?\d+$")
_HEX_INTEGER_RE = re.compile(r"^[+-]?&h[0-9a-f]+$", re.IGNORECASE)
_POWERSHELL_COMMAND_RE = re.compile(
    r"^\s*(?:powershell|pwsh)(?:\.exe)?\b(?P<arguments>.*)$",
    re.IGNORECASE | re.DOTALL,
)
_POWERSHELL_ENCODED_RE = re.compile(
    r"(?i)(?<!\S)-(?:ec|enc|encodedcommand)\s+"
    r"(?P<encoded>[A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])"
)
_KNOWN_HTA_SUFFIXES = frozenset({".hta", ".htm", ".html"})
_KNOWN_NON_HTA_SUFFIXES = frozenset(
    {
        ".au3",
        ".bat",
        ".cmd",
        ".js",
        ".jse",
        ".lua",
        ".nsi",
        ".ps1",
        ".sh",
        ".vbe",
        ".vbs",
    }
)


@dataclass(frozen=True)
class HtaConstantCommandLimits:
    """HTA定数dataflow復元に適用するhard limit。"""

    max_input_bytes: int = 2 * 1024 * 1024
    max_script_blocks: int = 16
    max_script_body_characters: int = 2 * 1024 * 1024
    max_statements: int = 20_000
    max_expression_characters: int = 2 * 1024 * 1024
    max_terms: int = 262_144
    max_output_bytes: int = 2 * 1024 * 1024
    max_work_units: int = 8 * 1024 * 1024


DEFAULT_LIMITS = HtaConstantCommandLimits()


class _Rejected(ValueError):
    """限定profileに一致しない入力を内部制御として表す。"""


class _LimitExceeded(ValueError):
    """hard limit到達を内部制御として表す。"""


@dataclass
class _Budget:
    limits: HtaConstantCommandLimits
    work_units: int = 0

    def work(self, amount: int) -> None:
        """処理量を加算し、上限超過時に停止する。"""

        if amount < 0:
            raise ValueError("処理量は0以上である必要があります")
        self.work_units += amount
        if self.work_units > self.limits.max_work_units:
            raise _LimitExceeded("max_work_units")


@dataclass(frozen=True)
class _Folded:
    value: str
    variables: frozenset[str]
    literal_terms: int
    chr_terms: int
    environment_terms: int


def _safety() -> dict[str, bool]:
    return {
        "sample_executed": False,
        "network_contacted": False,
        "html_rendered": False,
        "general_vbscript_interpreter_used": False,
        "eval_execute_invoked": False,
        "com_created": False,
        "command_started": False,
        "powershell_started": False,
        "raw_source_included": False,
        "raw_command_included": False,
    }


def _base_report(
    limits: HtaConstantCommandLimits,
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


def _hta_profile_signal(data: bytes) -> tuple[bool, str | None]:
    """全入力を複製せず、ASCII/UTF-16のHTML+VBScript anchorを確認する。"""

    ascii_html = re.search(
        rb"(?i)<(?:!doctype[\t ]+html|html\b|hta:application\b)", data
    )
    ascii_script = re.search(rb"(?i)<script\b", data)
    ascii_vbscript = re.search(rb"(?i)vbscript", data)
    if ascii_html and ascii_script and ascii_vbscript:
        return True, "ascii"
    for encoding in ("utf-16-le", "utf-16-be"):
        markers = {
            name: re.escape(name.encode(encoding))
            for name in (
                "<script",
                "vbscript",
                "<html",
                "<!doctype",
                "<hta:application",
            )
        }
        if (
            re.search(markers["<script"], data, re.IGNORECASE)
            and re.search(markers["vbscript"], data, re.IGNORECASE)
            and any(
                re.search(markers[name], data, re.IGNORECASE)
                for name in ("<html", "<!doctype", "<hta:application")
            )
        ):
            return True, encoding
    return False, None


def _applicability(
    data: bytes, source_name: str | None
) -> tuple[bool, dict[str, object]]:
    suffix = Path(source_name).suffix.casefold() if source_name else ""
    signal, encoding = _hta_profile_signal(data)
    known_hta = suffix in _KNOWN_HTA_SUFFIXES
    known_non_hta = suffix in _KNOWN_NON_HTA_SUFFIXES
    return (known_hta or (not known_non_hta and signal)), {
        "script_suffix": suffix or None,
        "known_hta_suffix": known_hta,
        "known_non_hta_suffix": known_non_hta,
        "strict_profile_lexical_signal": signal,
        "strict_profile_lexical_encoding": encoding,
        "lexical_scan_scope": "full_input",
    }


def _decode_source(data: bytes) -> tuple[str, str] | None:
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            text = data.decode(encoding)
        except UnicodeError:
            continue
        if "\x00" not in text:
            return text, encoding
    return None


def _unquote(value: str) -> str | None:
    value = value.strip()
    if len(value) < 2:
        return None
    if value[0] == value[-1] == '"':
        body = value[1:-1]
        index = 0
        output: list[str] = []
        while index < len(body):
            if body[index] != '"':
                output.append(body[index])
                index += 1
                continue
            if index + 1 >= len(body) or body[index + 1] != '"':
                return None
            output.append('"')
            index += 2
        return "".join(output)
    if value[0] == value[-1] == "'":
        return value[1:-1]
    return None


def _parse_attributes(value: str) -> dict[str, str] | None:
    attributes: dict[str, str] = {}
    position = 0
    for match in _ATTRIBUTE_RE.finditer(value):
        if value[position : match.start()].strip():
            return None
        name = match.group(1).casefold()
        decoded = _unquote(match.group(2))
        if decoded is None or name in attributes:
            return None
        attributes[name] = decoded
        position = match.end()
    if value[position:].strip():
        return None
    return attributes


def _is_vbscript_attributes(attributes: dict[str, str]) -> bool:
    if "src" in attributes:
        return False
    language = attributes.get("language", "").strip().casefold()
    media_type = attributes.get("type", "").strip().casefold()
    return language in {"vbscript", "vbs"} or media_type in {
        "text/vbscript",
        "application/x-vbscript",
    }


def _strip_comment(value: str) -> str:
    in_string = False
    index = 0
    while index < len(value):
        if value[index] == '"':
            if in_string and index + 1 < len(value) and value[index + 1] == '"':
                index += 2
                continue
            in_string = not in_string
        elif value[index] == "'" and not in_string:
            return value[:index].rstrip()
        index += 1
    return value.rstrip()


def _split_statements(
    value: str,
    *,
    limits: HtaConstantCommandLimits,
    budget: _Budget,
) -> list[str]:
    statements: list[str] = []
    start = 0
    in_string = False
    index = 0
    while index < len(value):
        budget.work(1)
        character = value[index]
        if character == '"':
            if in_string and index + 1 < len(value) and value[index + 1] == '"':
                budget.work(1)
                index += 2
                continue
            in_string = not in_string
        elif not in_string and character in ":\r\n":
            item = _strip_comment(value[start:index].strip())
            if item and not item.casefold().startswith("rem "):
                statements.append(item)
                if len(statements) > limits.max_statements:
                    raise _LimitExceeded("max_statements")
            if (
                character == "\r"
                and index + 1 < len(value)
                and value[index + 1] == "\n"
            ):
                budget.work(1)
                index += 1
            start = index + 1
        index += 1
    if in_string:
        raise _Rejected("unterminated_string")
    tail = _strip_comment(value[start:].strip())
    if tail and not tail.casefold().startswith("rem "):
        statements.append(tail)
    if len(statements) > limits.max_statements:
        raise _LimitExceeded("max_statements")
    return statements


def _split_top_level(value: str, separators: str, *, budget: _Budget) -> list[str]:
    output: list[str] = []
    start = 0
    depth = 0
    in_string = False
    index = 0
    while index < len(value):
        budget.work(1)
        character = value[index]
        if character == '"':
            if in_string and index + 1 < len(value) and value[index + 1] == '"':
                budget.work(1)
                index += 2
                continue
            in_string = not in_string
        elif not in_string:
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth < 0:
                    raise _Rejected("unbalanced_parentheses")
            elif depth == 0 and character in separators:
                term = value[start:index].strip()
                if not term:
                    raise _Rejected("empty_expression_term")
                output.append(term)
                start = index + 1
        index += 1
    if in_string or depth != 0:
        raise _Rejected("unbalanced_expression")
    term = value[start:].strip()
    if not term:
        raise _Rejected("empty_expression_term")
    output.append(term)
    return output


def _parse_integer(value: str) -> int | None:
    value = value.strip()
    if _INTEGER_RE.fullmatch(value):
        try:
            return int(value, 10)
        except ValueError:
            return None
    if _HEX_INTEGER_RE.fullmatch(value):
        sign = -1 if value.startswith("-") else 1
        digits = value.lstrip("+-")[2:]
        try:
            return sign * int(digits, 16)
        except ValueError:
            return None
    return None


def _combine(values: list[_Folded]) -> _Folded:
    return _Folded(
        value="".join(value.value for value in values),
        variables=frozenset().union(*(value.variables for value in values)),
        literal_terms=sum(value.literal_terms for value in values),
        chr_terms=sum(value.chr_terms for value in values),
        environment_terms=sum(value.environment_terms for value in values),
    )


def _fold_expression(
    expression: str,
    *,
    constants: dict[str, str],
    shell_name: str | None,
    limits: HtaConstantCommandLimits,
    budget: _Budget,
) -> _Folded:
    if len(expression) > limits.max_expression_characters:
        raise _LimitExceeded("max_expression_characters")
    terms = _split_top_level(expression, "&+", budget=budget)
    if len(terms) > limits.max_terms:
        raise _LimitExceeded("max_terms")
    if len(terms) > 1:
        return _combine(
            [
                _fold_expression(
                    term,
                    constants=constants,
                    shell_name=shell_name,
                    limits=limits,
                    budget=budget,
                )
                for term in terms
            ]
        )
    term = terms[0].strip()
    literal = _unquote(term)
    if literal is not None:
        budget.work(len(literal))
        return _Folded(literal, frozenset(), 1, 0, 0)
    character = _CHR_RE.fullmatch(term)
    if character is not None:
        integer = _parse_integer(character.group(2))
        maximum = 0xFFFF if character.group(1) else 0x7F
        if (
            integer is None
            or not 0 <= integer <= maximum
            or 0xD800 <= integer <= 0xDFFF
        ):
            raise _Rejected("unsupported_chr_constant")
        return _Folded(chr(integer), frozenset(), 0, 1, 0)
    environment = _EXPAND_ENV_RE.fullmatch(term)
    if environment is not None:
        if shell_name is None or environment.group(1).casefold() != shell_name:
            raise _Rejected("environment_receiver_mismatch")
        argument = _fold_expression(
            environment.group(2),
            constants=constants,
            shell_name=shell_name,
            limits=limits,
            budget=budget,
        )
        if argument.variables or argument.value.casefold() != "%comspec%":
            raise _Rejected("unsupported_environment_expansion")
        return _Folded(
            "%COMSPEC%",
            frozenset(),
            argument.literal_terms,
            argument.chr_terms,
            argument.environment_terms + 1,
        )
    if re.fullmatch(IDENTIFIER, term):
        normalized = term.casefold()
        if normalized not in constants:
            raise _Rejected("unresolved_variable")
        value = constants[normalized]
        budget.work(len(value))
        return _Folded(value, frozenset({normalized}), 0, 0, 0)
    if term.startswith("(") and term.endswith(")"):
        return _fold_expression(
            term[1:-1],
            constants=constants,
            shell_name=shell_name,
            limits=limits,
            budget=budget,
        )
    raise _Rejected("unsupported_expression_term")


def _command_is_valid(value: str, limits: HtaConstantCommandLimits) -> bool:
    if not 8 <= len(value.encode("utf-8")) <= limits.max_output_bytes:
        return False
    if "\x00" in value or not all(
        character.isprintable() or character in "\r\n\t" for character in value
    ):
        return False
    lowered = value.casefold()
    markers = ("%comspec%", "cmd.exe", "powershell", "pwsh", "wscript", "cscript")
    return any(marker in lowered for marker in markers)


def _decode_powershell_encoded_command(
    value: str,
    *,
    limits: HtaConstantCommandLimits,
    budget: _Budget,
) -> bytes | None:
    command = _POWERSHELL_COMMAND_RE.fullmatch(value)
    if command is None:
        return None
    matches = list(_POWERSHELL_ENCODED_RE.finditer(command.group("arguments")))
    if len(matches) != 1:
        return None
    encoded = matches[0].group("encoded")
    if len(encoded) > (limits.max_output_bytes * 4 // 3) + 4:
        raise _LimitExceeded("max_output_bytes")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if (
        base64.b64encode(blob).decode() != encoded
        or not 16 <= len(blob) <= limits.max_output_bytes
    ):
        return None
    if len(blob) % 2:
        return None
    try:
        text = blob.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    text = text.removeprefix("\ufeff")
    if (
        not text.strip()
        or "\x00" in text
        or not all(
            character.isprintable() or character in "\r\n\t" for character in text
        )
    ):
        return None
    lowered = text.casefold()
    markers = (
        "invoke-webrequest",
        "invoke-restmethod",
        "start-process",
        "downloadfile",
        "downloadstring",
        "wget",
        "iwr",
        "$env:",
        "new-object",
    )
    if not any(marker in lowered for marker in markers):
        return None
    output = text.encode("utf-8")
    if len(output) > limits.max_output_bytes:
        raise _LimitExceeded("max_output_bytes")
    budget.work(len(encoded) + len(blob) + len(output))
    return output


def _analyze_block(
    body: str,
    *,
    limits: HtaConstantCommandLimits,
    budget: _Budget,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    statements = _split_statements(body, limits=limits, budget=budget)
    declared: set[str] = set()
    constants: dict[str, str] = {}
    assigned: set[str] = set()
    shell_name: str | None = None
    shell_released = False
    close_seen = False
    sink: _Folded | None = None
    sink_window_style: int | None = None
    sink_wait: bool | None = None
    for statement in statements:
        dimension = _DIM_RE.fullmatch(statement)
        if dimension is not None:
            names = [item.strip() for item in dimension.group(1).split(",")]
            if not names or any(
                re.fullmatch(IDENTIFIER, item) is None for item in names
            ):
                raise _Rejected("invalid_dim")
            normalized = {item.casefold() for item in names}
            if declared.intersection(normalized):
                raise _Rejected("duplicate_declaration")
            declared.update(normalized)
            continue
        create = _SET_CREATEOBJECT_RE.fullmatch(statement)
        if create is not None:
            name = create.group(1).casefold()
            if name not in declared or name in assigned or shell_name is not None:
                raise _Rejected("ambiguous_shell_assignment")
            progid = _fold_expression(
                create.group(2),
                constants=constants,
                shell_name=None,
                limits=limits,
                budget=budget,
            )
            if progid.variables or progid.value.casefold() != "wscript.shell":
                raise _Rejected("unsupported_createobject")
            assigned.add(name)
            shell_name = name
            continue
        release = _SET_NOTHING_RE.fullmatch(statement)
        if release is not None:
            name = release.group(1).casefold()
            if (
                shell_name is None
                or name != shell_name
                or sink is None
                or shell_released
            ):
                raise _Rejected("invalid_shell_release")
            shell_released = True
            continue
        run = _RUN_RE.fullmatch(statement)
        if run is not None:
            if (
                sink is not None
                or shell_name is None
                or run.group(1).casefold() != shell_name
            ):
                raise _Rejected("ambiguous_run_sink")
            arguments = _split_top_level(run.group(2), ",", budget=budget)
            if len(arguments) not in {2, 3}:
                raise _Rejected("unsupported_run_arguments")
            sink = _fold_expression(
                arguments[0],
                constants=constants,
                shell_name=shell_name,
                limits=limits,
                budget=budget,
            )
            sink_window_style = _parse_integer(arguments[1])
            if sink_window_style is None or not -10 <= sink_window_style <= 10:
                raise _Rejected("unsupported_window_style")
            if len(arguments) == 3:
                if arguments[2].strip().casefold() not in {"true", "false"}:
                    raise _Rejected("unsupported_wait_argument")
                sink_wait = arguments[2].strip().casefold() == "true"
            if not _command_is_valid(sink.value, limits):
                raise _Rejected("command_validation_failed")
            continue
        assignment = _ASSIGN_RE.fullmatch(statement)
        if assignment is not None:
            name = assignment.group(1).casefold()
            if name not in declared or name in assigned or sink is not None:
                raise _Rejected("ambiguous_constant_assignment")
            value = _fold_expression(
                assignment.group(2),
                constants=constants,
                shell_name=shell_name,
                limits=limits,
                budget=budget,
            )
            if value.variables:
                raise _Rejected("aliased_constant_assignment")
            if len(value.value.encode("utf-8")) > limits.max_output_bytes:
                raise _LimitExceeded("max_output_bytes")
            constants[name] = value.value
            assigned.add(name)
            continue
        if _CLOSE_RE.fullmatch(statement):
            if sink is None or close_seen:
                raise _Rejected("invalid_close_order")
            close_seen = True
            continue
        raise _Rejected("unsupported_statement")
    if shell_name is None or sink is None:
        raise _Rejected("required_dataflow_not_found")
    command = sink.value.encode("utf-8")
    artifacts: list[tuple[str, bytes]] = [
        ("hta-constant-wscript-shell-run-command.cmd", command)
    ]
    payloads: list[tuple[str, bytes]] = []
    encoded_scripts: list[bytes] = []
    for variable in sorted(sink.variables):
        value = constants[variable]
        lowered = value.lstrip().casefold()
        if lowered.startswith(("powershell ", "powershell.exe ", "pwsh ", "pwsh.exe ")):
            encoded = value.encode("utf-8")
            if encoded != command:
                payloads.append(("hta-constant-powershell-command.cmd", encoded))
            decoded = _decode_powershell_encoded_command(
                value,
                limits=limits,
                budget=budget,
            )
            if decoded is not None and decoded not in encoded_scripts:
                encoded_scripts.append(decoded)
    artifacts.extend(payloads)
    artifacts.extend(
        ("hta-powershell-encoded-command.ps1", value) for value in encoded_scripts
    )
    candidate = {
        "statement_count": len(statements),
        "declared_variable_count": len(declared),
        "constant_assignment_count": len(constants),
        "run_command_sha256": hashlib.sha256(command).hexdigest(),
        "run_command_size": len(command),
        "referenced_constant_count": len(sink.variables),
        "literal_term_count": sink.literal_terms,
        "chr_term_count": sink.chr_terms,
        "environment_term_count": sink.environment_terms,
        "window_style": sink_window_style,
        "wait_argument_present": sink_wait is not None,
        "wait": sink_wait,
        "shell_released": shell_released,
        "window_closed": close_seen,
        "powershell_child_count": len(payloads),
        "powershell_encoded_script_count": len(encoded_scripts),
        "powershell_encoded_script_sha256": [
            hashlib.sha256(value).hexdigest() for value in encoded_scripts
        ],
        "powershell_encoded_script_size": [len(value) for value in encoded_scripts],
        "artifact_count": len(artifacts),
    }
    return candidate, artifacts


def recover_hta_constant_commands(
    data: bytes,
    *,
    limits: HtaConstantCommandLimits = DEFAULT_LIMITS,
    source_name: str | None = None,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """限定HTA dataflowから ``Run`` commandを検体非実行で復元する。"""

    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    applicable, applicability = _applicability(data, source_name)
    if not applicable:
        report = _base_report(limits, status="not_applicable")
        report.update(
            {
                "candidate_set_complete": True,
                "applicability": applicability,
            }
        )
        return report, []
    if len(data) > limits.max_input_bytes:
        report = _base_report(limits, status="input_limit_exceeded")
        report["applicability"] = applicability
        return report, []
    decoded = _decode_source(data)
    if decoded is None:
        return _base_report(limits, status="text_decode_failed"), []
    text, encoding = decoded
    lowered = text.casefold()
    if "<script" not in lowered or not any(
        marker in lowered for marker in ("<html", "<!doctype html", "<hta:application")
    ):
        report = _base_report(limits, status="not_applicable")
        report.update(
            {
                "encoding": encoding,
                "candidate_set_complete": True,
                "applicability": applicability,
            }
        )
        return report, []
    budget = _Budget(limits)
    script_open_count = len(re.findall(r"(?i)<script\b", text))
    matches = list(_SCRIPT_RE.finditer(text))
    if script_open_count > limits.max_script_blocks:
        report = _base_report(limits, status="limit_exceeded")
        report.update({"limit": "max_script_blocks", "applicability": applicability})
        return report, []
    if script_open_count != len(matches):
        report = _base_report(limits, status="profile_rejected")
        report.update(
            {
                "rejections": {"unbalanced_script_blocks": 1},
                "applicability": applicability,
            }
        )
        return report, []
    candidates: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    rejections: Counter[str] = Counter()
    vbscript_blocks = 0
    seen: set[str] = set()
    try:
        for block_index, match in enumerate(matches, 1):
            attributes = _parse_attributes(match.group("attrs"))
            if attributes is None:
                if "vbscript" in match.group("attrs").casefold():
                    rejections["invalid_script_attributes"] += 1
                continue
            if not _is_vbscript_attributes(attributes):
                continue
            vbscript_blocks += 1
            body = match.group("body")
            if len(body) > limits.max_script_body_characters:
                raise _LimitExceeded("max_script_body_characters")
            try:
                candidate, recovered = _analyze_block(
                    body,
                    limits=limits,
                    budget=budget,
                )
            except _Rejected as exc:
                rejections[str(exc)] += 1
                continue
            digest = str(candidate["run_command_sha256"])
            if digest in seen:
                continue
            seen.add(digest)
            candidate = {"script_block_index": block_index, **candidate}
            candidates.append(candidate)
            artifacts.extend(recovered)
    except _LimitExceeded as exc:
        report = _base_report(limits, status="limit_exceeded")
        report.update(
            {
                "encoding": encoding,
                "limit": str(exc),
                "script_block_count": len(matches),
                "vbscript_block_count": vbscript_blocks,
                "rejections": dict(rejections),
                "work_units": budget.work_units,
                "applicability": applicability,
            }
        )
        return report, []
    if len(candidates) > 1:
        rejections["ambiguous_distinct_run_commands"] += 1
        report = _base_report(limits, status="profile_rejected")
        report.update(
            {
                "encoding": encoding,
                "script_block_count": len(matches),
                "vbscript_block_count": vbscript_blocks,
                "candidate_set_complete": False,
                "candidate_count": len(candidates),
                "candidates": candidates,
                "rejections": dict(rejections),
                "work_units": budget.work_units,
                "applicability": applicability,
            }
        )
        return report, []
    report = _base_report(
        limits,
        status="artifacts_recovered" if candidates else "pattern_not_found",
    )
    report.update(
        {
            "encoding": encoding,
            "script_block_count": len(matches),
            "vbscript_block_count": vbscript_blocks,
            "candidate_set_complete": not bool(vbscript_blocks and rejections),
            "candidate_count": len(candidates),
            "candidates": candidates,
            "rejections": dict(rejections),
            "work_units": budget.work_units,
            "applicability": applicability,
        }
    )
    if candidates and rejections:
        report["status"] = "partial_profile_rejection"
        report["candidate_set_complete"] = False
        return report, []
    if not vbscript_blocks and rejections:
        report["status"] = "profile_rejected"
        report["candidate_set_complete"] = False
    return report, artifacts
