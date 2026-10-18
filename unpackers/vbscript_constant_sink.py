"""VBScriptの固定逆slice型 ``Execute`` 引数を非実行で復元する。

このmoduleはVBScript interpreterではない。単一文字列literalを、厳密に確認した
1-based固定slice関数へ渡し、その戻り値が単独の ``Execute`` 引数になる場合だけを
扱う。一般式、COM、WMI、PowerShell、``Eval`` / ``Execute`` は一切実行しない。
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass

PROFILE_NAME = "vbscript-constant-direct-execute-inverse-slice-v1"
IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_IDENTIFIER_RE = re.compile(rf"^{IDENTIFIER}$", re.IGNORECASE)
_PROCEDURE_HEADER_RE = re.compile(
    rf"^(?:(?:public|private|default)\s+)*(function|sub)\s+({IDENTIFIER})\b(.*)$",
    re.IGNORECASE,
)
_END_PROCEDURE_RE = re.compile(r"^end\s+(function|sub)$", re.IGNORECASE)
_STRICT_FUNCTION_ARGUMENT_RE = re.compile(
    rf"^\(\s*({IDENTIFIER})\s*\)$",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(
    rf"^(?:set\s+)?({IDENTIFIER})\s*=\s*(.*)$",
    re.IGNORECASE,
)
_DIRECT_EXECUTE_RE = re.compile(
    rf"^execute\s*(?:\(\s*({IDENTIFIER})\s*\)|\s+({IDENTIFIER}))$",
    re.IGNORECASE,
)
_EXECUTE_PREFIX_RE = re.compile(r"^execute\b", re.IGNORECASE)
_CALL_LITERAL_RE = re.compile(
    rf'^({IDENTIFIER})\s*\(\s*"((?:""|[^"])*)"\s*\)$',
    re.IGNORECASE,
)
_WHILE_RE = re.compile(
    rf"^while\s+({IDENTIFIER})\s*<=\s*len\s*\(\s*({IDENTIFIER})\s*\)"
    r"\s*-\s*(.+)$",
    re.IGNORECASE,
)
_APPEND_RE = re.compile(
    rf"^({IDENTIFIER})\s*=\s*({IDENTIFIER})\s*&\s*mid\s*\(\s*"
    rf"({IDENTIFIER})\s*,\s*({IDENTIFIER})\s*,\s*(.+)\)$",
    re.IGNORECASE,
)
_INCREMENT_RE = re.compile(
    rf"^({IDENTIFIER})\s*=\s*({IDENTIFIER})\s*\+\s*(.+)$",
    re.IGNORECASE,
)
_RETURN_RE = re.compile(
    rf"^({IDENTIFIER})\s*=\s*({IDENTIFIER})$",
    re.IGNORECASE,
)
_REPEATED_CHARACTER_APPEND_RE = re.compile(
    rf'^({IDENTIFIER})\s*=\s*\1\s*(?:&|\+)\s*"((?:""|[^"])*)"$',
    re.IGNORECASE,
)
_ASC_MID_RE = re.compile(
    rf"^({IDENTIFIER})\s*=\s*asc\s*\(\s*mid\s*\(\s*({IDENTIFIER})\s*,"
    r"\s*(.+?)\s*,\s*(.+?)\s*\)\s*\)$",
    re.IGNORECASE,
)
_SELF_INTEGER_ARITHMETIC_RE = re.compile(
    rf"^({IDENTIFIER})\s*=\s*\1\s*([+-])\s*(.+)$",
    re.IGNORECASE,
)
_INTEGER_TOKEN_RE = re.compile(
    r"\s*(?:(?P<hex>&[Hh][0-9A-Fa-f]+)|(?P<int>\d+)|(?P<op>[()+\-*]))"
)
_STRING_LITERAL_RE = re.compile(r'^"(?:""|[^"])*"$')
_IGNORABLE_PURE_NO_ARGUMENT_RE = re.compile(
    r"^(?:date|now|rnd|time|timer)(?:\s*\(\s*\))?$",
    re.IGNORECASE,
)
_IGNORABLE_STANDALONE_DECOY_RE = re.compile(r"^randomize$", re.IGNORECASE)
_IGNORABLE_PURE_STRING_ARGUMENT_RE = re.compile(
    r"^(?:lcase|len|lenb|ltrim|rtrim|strreverse|timevalue|trim|ucase)"
    r'\s*\(\s*"(?:""|[^"])*"\s*\)$',
    re.IGNORECASE,
)
_PURE_STRING_TRANSFORM_IDENTIFIER_RE = re.compile(
    rf"^(?:lcase|ltrim|rtrim|strreverse|trim|ucase)\s*\(\s*({IDENTIFIER})\s*\)$",
    re.IGNORECASE,
)
_PURE_LITERAL_SLICE_RE = re.compile(
    r'^(?:mid|midb)\s*\(\s*"(?:""|[^"])*"\s*,\s*(.+?)\s*,\s*(.+?)\s*\)$',
    re.IGNORECASE,
)
_OUTPUT_TOKEN_RE = re.compile(
    rf'"(?:""|[^"])*"|&[Hh][0-9A-Fa-f]+|\d+|{IDENTIFIER}|'
    r"<=|>=|<>|[&()+\-*/\\^=,:.]",
    re.IGNORECASE,
)
_CONTROL_PREFIX_RE = re.compile(
    r"^(?:if|elseif|else|end\s+if|for|next|do|loop|select|case|end\s+select|"
    r"with|end\s+with|goto|exit|on\s+error|call|execute|executeglobal|eval)\b",
    re.IGNORECASE,
)

MAXIMUM_INTEGER_TOKENS = 512
MAXIMUM_INTEGER_NESTING = 64
MAXIMUM_INTEGER_LITERAL_CHARACTERS = 64


@dataclass(frozen=True)
class VbscriptConstantSinkLimits:
    """固定slice復元に用いるhard limit。"""

    max_input_bytes: int = 2 * 1024 * 1024
    max_statements: int = 50_000
    max_functions: int = 256
    max_sinks: int = 256
    max_attempts: int = 512
    max_literal_characters: int = 1024 * 1024
    max_candidate_count: int = 128
    max_output_bytes: int = 2 * 1024 * 1024
    max_slice_width: int = 64
    max_work_units: int = 8 * 1024 * 1024
    max_integer_absolute: int = 16 * 1024 * 1024


DEFAULT_LIMITS = VbscriptConstantSinkLimits()


@dataclass(frozen=True)
class _Statement:
    line: int
    text: str


@dataclass(frozen=True)
class _Procedure:
    kind: str
    name: str
    parameter: str | None
    line: int
    body: tuple[_Statement, ...]


@dataclass(frozen=True)
class _SliceProfile:
    function_name: str
    parameter: str
    start: int
    tail: int
    step: int
    width: int
    width_resolution: str


class _LimitExceeded(Exception):
    def __init__(self, limit_name: str) -> None:
        self.limit_name = limit_name
        super().__init__(limit_name)


class _LexicalRejected(Exception):
    pass


class _Budget:
    def __init__(self, limits: VbscriptConstantSinkLimits) -> None:
        self.limits = limits
        self.work_units = 0
        self.attempts = 0

    def work(self, amount: int) -> None:
        if amount < 0:
            raise ValueError("work amountは非負である必要があります")
        self.work_units += amount
        if self.work_units > self.limits.max_work_units:
            raise _LimitExceeded("max_work_units")

    def attempt(self) -> None:
        self.attempts += 1
        if self.attempts > self.limits.max_attempts:
            raise _LimitExceeded("max_attempts")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safety() -> dict[str, object]:
    return {
        "sample_executed": False,
        "network_contacted": False,
        "general_vbscript_interpreter_used": False,
        "eval_execute_invoked": False,
        "com_created": False,
        "wmi_invoked": False,
        "powershell_started": False,
        "process_started": False,
        "raw_source_included": False,
        "raw_literal_included": False,
        "recovered_output_in_report": False,
    }


def _base_report(
    limits: VbscriptConstantSinkLimits,
    *,
    status: str,
    budget: _Budget | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "profile": PROFILE_NAME,
        "candidate_set_complete": False,
        "attempt_count": 0 if budget is None else budget.attempts,
        "work_units": 0 if budget is None else budget.work_units,
        "limits": asdict(limits),
        "candidates": [],
        "rejections": {},
        "safety": _safety(),
    }


def _decode_source(data: bytes) -> tuple[str, str] | None:
    if data.startswith(b"\xff\xfe"):
        encoding = "utf-16-le"
        source = data[2:]
    elif data.startswith(b"\xfe\xff"):
        encoding = "utf-16-be"
        source = data[2:]
    elif data.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
        source = data
    else:
        for encoding in ("utf-8", "cp1252"):
            try:
                text = data.decode(encoding)
            except UnicodeDecodeError:
                continue
            if "\x00" not in text:
                return text, encoding
        return None
    try:
        text = source.decode(encoding)
    except UnicodeDecodeError:
        return None
    if "\x00" in text:
        return None
    return text, encoding


def _split_line(raw_line: str) -> list[str] | None:
    """引用符外のcommentとcolonだけを字句的に処理する。"""

    statements: list[str] = []
    current: list[str] = []
    index = 0
    in_string = False
    while index < len(raw_line):
        character = raw_line[index]
        if in_string:
            current.append(character)
            if character == '"':
                if index + 1 < len(raw_line) and raw_line[index + 1] == '"':
                    current.append('"')
                    index += 2
                    continue
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            current.append(character)
            index += 1
            continue
        if character == "'":
            break
        if character == ":":
            value = "".join(current).strip()
            # ``Rem`` はstatementの終端ではなく、その行の残り全体をcommentにする。
            # comment内の句読点 ``:`` を次のstatementの開始とみなすと、自然文を
            # executable statementとして誤って公開してしまうため、ここで行走査を
            # 終える。先行statementがある ``x = 1: Rem ...`` も同じ規則になる。
            if re.match(r"^rem(?:\s|$)", value, re.IGNORECASE):
                break
            if value:
                statements.append(value)
            current = []
            index += 1
            continue
        current.append(character)
        index += 1
    if in_string:
        return None
    value = "".join(current).strip()
    if value and not re.match(r"^rem(?:\s|$)", value, re.IGNORECASE):
        statements.append(value)
    return statements


def _scan_statements(
    text: str,
    *,
    limits: VbscriptConstantSinkLimits,
    budget: _Budget,
) -> list[_Statement]:
    budget.work(len(text))
    statements: list[_Statement] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        parts = _split_line(raw_line)
        if parts is None:
            raise _LexicalRejected("unterminated_string_literal")
        for value in parts:
            statements.append(_Statement(line=line_number, text=value))
            if len(statements) > limits.max_statements:
                raise _LimitExceeded("max_statements")
    return statements


def _partition_procedures(
    statements: list[_Statement],
    *,
    limits: VbscriptConstantSinkLimits,
) -> tuple[list[_Statement], list[_Procedure]] | None:
    top_level: list[_Statement] = []
    procedures: list[_Procedure] = []
    current_kind: str | None = None
    current_name = ""
    current_parameter: str | None = None
    current_line = 0
    current_body: list[_Statement] = []
    for statement in statements:
        header = _PROCEDURE_HEADER_RE.fullmatch(statement.text)
        ending = _END_PROCEDURE_RE.fullmatch(statement.text)
        if current_kind is None:
            if ending is not None:
                return None
            if header is None:
                top_level.append(statement)
                continue
            current_kind = header.group(1).casefold()
            current_name = header.group(2)
            current_line = statement.line
            argument = _STRICT_FUNCTION_ARGUMENT_RE.fullmatch(header.group(3).strip())
            current_parameter = (
                argument.group(1)
                if current_kind == "function" and argument is not None
                else None
            )
            current_body = []
            continue
        if header is not None:
            return None
        if ending is None:
            current_body.append(statement)
            continue
        if ending.group(1).casefold() != current_kind:
            return None
        procedures.append(
            _Procedure(
                kind=current_kind,
                name=current_name,
                parameter=current_parameter,
                line=current_line,
                body=tuple(current_body),
            )
        )
        if len(procedures) > limits.max_functions:
            raise _LimitExceeded("max_functions")
        current_kind = None
        current_name = ""
        current_parameter = None
        current_body = []
    if current_kind is not None:
        return None
    return top_level, procedures


class _IntegerParser:
    def __init__(self, expression: str, maximum: int) -> None:
        self.tokens: list[str] = []
        position = 0
        while position < len(expression):
            match = _INTEGER_TOKEN_RE.match(expression, position)
            if match is None:
                raise ValueError("unsupported_integer_expression")
            token = match.group("hex") or match.group("int") or match.group("op")
            if len(self.tokens) >= MAXIMUM_INTEGER_TOKENS:
                raise ValueError("integer_expression_token_limit_exceeded")
            if (
                match.group("hex") is not None or match.group("int") is not None
            ) and len(token) > MAXIMUM_INTEGER_LITERAL_CHARACTERS:
                raise ValueError("integer_literal_length_exceeded")
            self.tokens.append(token)
            position = match.end()
        self.index = 0
        self.maximum = maximum

    def parse(self) -> int:
        if not self.tokens:
            raise ValueError("empty_integer_expression")
        value = self._expression(0)
        if self.index != len(self.tokens):
            raise ValueError("trailing_integer_tokens")
        return value

    def _bounded(self, value: int) -> int:
        if abs(value) > self.maximum:
            raise ValueError("integer_expression_out_of_range")
        return value

    def _expression(self, depth: int) -> int:
        value = self._term(depth)
        while self._peek() in {"+", "-"}:
            operator = self._take()
            right = self._term(depth)
            value = self._bounded(value + right if operator == "+" else value - right)
        return value

    def _term(self, depth: int) -> int:
        value = self._factor(depth)
        while self._peek() == "*":
            self._take()
            value = self._bounded(value * self._factor(depth))
        return value

    def _factor(self, depth: int) -> int:
        if depth >= MAXIMUM_INTEGER_NESTING:
            raise ValueError("integer_expression_nesting_limit_exceeded")
        token = self._take()
        if token in {"+", "-"}:
            value = self._factor(depth + 1)
            return value if token == "+" else self._bounded(-value)
        if token == "(":
            value = self._expression(depth + 1)
            if self._take() != ")":
                raise ValueError("unbalanced_integer_expression")
            return value
        if token.casefold().startswith("&h"):
            return self._bounded(int(f"0x{token[2:]}", 0))
        if token.isdecimal():
            return self._bounded(int(token, 10))
        raise ValueError("invalid_integer_factor")

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected_integer_expression_end")
        self.index += 1
        return token


def _constant_integer(expression: str, maximum: int) -> int | None:
    try:
        return _IntegerParser(expression.strip(), maximum).parse()
    except (RecursionError, TypeError, ValueError):
        return None


def _split_ampersand(expression: str) -> list[str] | None:
    terms: list[str] = []
    current: list[str] = []
    index = 0
    in_string = False
    while index < len(expression):
        character = expression[index]
        if in_string:
            current.append(character)
            if character == '"':
                if index + 1 < len(expression) and expression[index + 1] == '"':
                    current.append('"')
                    index += 2
                    continue
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            current.append(character)
            index += 1
            continue
        if character == "&" and expression[index : index + 2].casefold() != "&h":
            value = "".join(current).strip()
            if not value:
                return None
            terms.append(value)
            current = []
            index += 1
            continue
        current.append(character)
        index += 1
    if in_string:
        return None
    value = "".join(current).strip()
    if not value:
        return None
    terms.append(value)
    return terms


def _is_ignored_constant_assignment(
    statement: str,
    *,
    maximum: int,
    constant_string_identifiers: set[str] | None = None,
) -> bool:
    """slice stateへ触れない、有界なpure定数代入だけを許す。"""

    assignment = _ASSIGNMENT_RE.fullmatch(statement)
    if assignment is None:
        return False
    expression = assignment.group(2).strip()
    if _is_constant_string_expression(
        expression,
        maximum=maximum,
        constant_string_identifiers=constant_string_identifiers or set(),
    ):
        return True
    if _IGNORABLE_PURE_NO_ARGUMENT_RE.fullmatch(expression) is not None:
        return True
    if _IGNORABLE_PURE_STRING_ARGUMENT_RE.fullmatch(expression) is not None:
        return True
    return _constant_integer(expression, maximum) is not None


def _is_constant_string_expression(
    expression: str,
    *,
    maximum: int,
    constant_string_identifiers: set[str],
) -> bool:
    """literalまたは既知literal由来のpure文字列式だけを認識する。"""

    terms = _split_ampersand(expression)
    if terms is not None and all(_STRING_LITERAL_RE.fullmatch(term) for term in terms):
        return True
    transform = _PURE_STRING_TRANSFORM_IDENTIFIER_RE.fullmatch(expression)
    if (
        transform is not None
        and transform.group(1).casefold() in constant_string_identifiers
    ):
        return True
    literal_slice = _PURE_LITERAL_SLICE_RE.fullmatch(expression)
    if literal_slice is None:
        return False
    start = _constant_integer(literal_slice.group(1), maximum)
    length = _constant_integer(literal_slice.group(2), maximum)
    return start is not None and start >= 1 and length is not None and length >= 0


def _identifier_tokens(statement: str) -> set[str]:
    without_literals = re.sub(r'"(?:""|[^"])*"', " ", statement)
    return {
        token.casefold()
        for token in re.findall(IDENTIFIER, without_literals, flags=re.IGNORECASE)
    }


def _resolve_repeated_character_integer_constants(
    statements: list[_Statement],
    *,
    limits: VbscriptConstantSinkLimits,
) -> dict[str, tuple[int, str]]:
    """反復1文字buffer由来の ``Asc(Mid(...))`` 定数だけを解決する。"""

    accumulator_candidates: dict[str, set[str]] = {}
    accumulator_assignment_count: Counter[str] = Counter()
    for statement in statements:
        assignment = _ASSIGNMENT_RE.fullmatch(statement.text)
        if assignment is not None:
            accumulator_assignment_count[assignment.group(1).casefold()] += 1
        append = _REPEATED_CHARACTER_APPEND_RE.fullmatch(statement.text)
        if append is None:
            continue
        value = _decode_vb_string(append.group(2))
        if len(value) == 1 and ord(value) <= 0x7F:
            accumulator_candidates.setdefault(append.group(1).casefold(), set()).add(
                value
            )
    accumulators = {
        name: next(iter(values))
        for name, values in accumulator_candidates.items()
        if len(values) == 1 and accumulator_assignment_count[name] == 1
    }

    resolved: dict[str, tuple[int, str]] = {}
    assignment_count: Counter[str] = Counter()
    for statement in statements:
        assignment = _ASSIGNMENT_RE.fullmatch(statement.text)
        if assignment is None:
            continue
        target = assignment.group(1).casefold()
        assignment_count[target] += 1
        asc_mid = _ASC_MID_RE.fullmatch(statement.text)
        if asc_mid is not None:
            source = asc_mid.group(2).casefold()
            index = _constant_integer(asc_mid.group(3), limits.max_integer_absolute)
            width = _constant_integer(asc_mid.group(4), limits.max_integer_absolute)
            if (
                source in accumulators
                and index is not None
                and index >= 1
                and width == 1
            ):
                resolved[target] = (
                    ord(accumulators[source]),
                    "repeated_ascii_character_asc_mid_v1",
                )
                continue
        arithmetic = _SELF_INTEGER_ARITHMETIC_RE.fullmatch(statement.text)
        if arithmetic is not None and target in resolved:
            operand = _constant_integer(
                arithmetic.group(3), limits.max_integer_absolute
            )
            if operand is not None:
                current, profile = resolved[target]
                value = (
                    current + operand
                    if arithmetic.group(2) == "+"
                    else current - operand
                )
                if abs(value) <= limits.max_integer_absolute:
                    resolved[target] = (value, profile)
                    continue
        # 既に解決したtargetへ別形状の再代入があれば曖昧として破棄する。
        resolved.pop(target, None)
    return {
        name: value for name, value in resolved.items() if assignment_count[name] >= 1
    }


def _match_slice_profile(
    procedure: _Procedure,
    *,
    limits: VbscriptConstantSinkLimits,
    budget: _Budget,
    external_integer_constants: dict[str, tuple[int, str]],
) -> tuple[_SliceProfile | None, str | None]:
    budget.attempt()
    if procedure.kind != "function" or procedure.parameter is None:
        return None, "unsupported_function_signature"
    body = list(procedure.body)
    while_matches: list[tuple[int, re.Match[str]]] = []
    for index, statement in enumerate(body):
        match = _WHILE_RE.fullmatch(statement.text)
        if match is not None:
            while_matches.append((index, match))
    if len(while_matches) != 1:
        return None, "ambiguous_while_shape"
    while_index, while_match = while_matches[0]
    index_name = while_match.group(1)
    parameter_name = while_match.group(2)
    if parameter_name.casefold() != procedure.parameter.casefold():
        return None, "parameter_mismatch"
    tail = _constant_integer(while_match.group(3), limits.max_integer_absolute)
    if tail is None or tail < 0:
        return None, "nonconstant_tail"

    init_matches: list[tuple[int, int]] = []
    for index, statement in enumerate(body[:while_index]):
        assignment = _ASSIGNMENT_RE.fullmatch(statement.text)
        if (
            assignment is None
            or assignment.group(1).casefold() != index_name.casefold()
        ):
            continue
        value = _constant_integer(assignment.group(2), limits.max_integer_absolute)
        if value is not None:
            init_matches.append((index, value))
    if len(init_matches) != 1 or init_matches[0][1] < 1:
        return None, "ambiguous_start"
    init_index, start = init_matches[0]

    wend_indices = [
        index
        for index, statement in enumerate(body)
        if statement.text.casefold() == "wend"
    ]
    if len(wend_indices) != 1 or wend_indices[0] <= while_index:
        return None, "ambiguous_wend"
    wend_index = wend_indices[0]

    append_matches: list[tuple[int, re.Match[str]]] = []
    increment_matches: list[tuple[int, re.Match[str]]] = []
    for index in range(while_index + 1, wend_index):
        statement = body[index].text
        append = _APPEND_RE.fullmatch(statement)
        if append is not None:
            append_matches.append((index, append))
        increment = _INCREMENT_RE.fullmatch(statement)
        if increment is not None:
            increment_matches.append((index, increment))
    if len(append_matches) != 1:
        return None, "ambiguous_append"
    append_index, append_match = append_matches[0]
    output_name = append_match.group(1)
    if (
        append_match.group(2).casefold() != output_name.casefold()
        or append_match.group(3).casefold() != procedure.parameter.casefold()
        or append_match.group(4).casefold() != index_name.casefold()
    ):
        return None, "append_state_mismatch"
    width = _constant_integer(append_match.group(5), limits.max_integer_absolute)
    width_resolution = "inline_constant_integer_v1"
    if width is None and _IDENTIFIER_RE.fullmatch(append_match.group(5).strip()):
        external = external_integer_constants.get(
            append_match.group(5).strip().casefold()
        )
        if external is not None:
            width, width_resolution = external
    if width is None or not 1 <= width <= limits.max_slice_width:
        return None, "unsupported_slice_width"
    valid_increments: list[tuple[int, int]] = []
    for index, increment in increment_matches:
        if (
            increment.group(1).casefold() == index_name.casefold()
            and increment.group(2).casefold() == index_name.casefold()
        ):
            step = _constant_integer(increment.group(3), limits.max_integer_absolute)
            if step is not None:
                valid_increments.append((index, step))
    if len(valid_increments) != 1 or valid_increments[0][1] < 1:
        return None, "ambiguous_step"
    increment_index, step = valid_increments[0]
    if append_index >= increment_index:
        return None, "invalid_loop_order"

    returns: list[tuple[int, re.Match[str]]] = []
    for index in range(wend_index + 1, len(body)):
        match = _RETURN_RE.fullmatch(body[index].text)
        if match is not None and match.group(1).casefold() == procedure.name.casefold():
            returns.append((index, match))
    if len(returns) != 1 or returns[0][1].group(2).casefold() != output_name.casefold():
        return None, "ambiguous_return"
    return_index = returns[0][0]

    core_indices = {
        init_index,
        while_index,
        append_index,
        increment_index,
        wend_index,
        return_index,
    }
    core_identifiers = {
        procedure.name.casefold(),
        procedure.parameter.casefold(),
        index_name.casefold(),
        output_name.casefold(),
    }
    constant_string_identifiers: set[str] = set()
    for index, statement in enumerate(body):
        if index in core_indices:
            continue
        if _CONTROL_PREFIX_RE.match(statement.text):
            return None, "unsupported_control_flow"
        if _identifier_tokens(statement.text) & core_identifiers:
            return None, "slice_state_referenced_by_extra_statement"
        # 引数なし ``Randomize`` はPRNG stateだけを変更し、固定sliceの入力、
        # cursor、出力へ触れない。引数付きや別のstandalone statementは従来どおり
        # 拒否し、一般VBScript評価へ広げない。
        if _IGNORABLE_STANDALONE_DECOY_RE.fullmatch(statement.text) is not None:
            continue
        assignment = _ASSIGNMENT_RE.fullmatch(statement.text)
        target = assignment.group(1).casefold() if assignment is not None else None
        if target is not None:
            # 同じ変数の再代入は、現在の式を評価する前に既知定数性を失う。
            constant_string_identifiers.discard(target)
        if not _is_ignored_constant_assignment(
            statement.text,
            maximum=limits.max_integer_absolute,
            constant_string_identifiers=constant_string_identifiers,
        ):
            return None, "nonconstant_extra_statement"
        if assignment is not None and _is_constant_string_expression(
            assignment.group(2).strip(),
            maximum=limits.max_integer_absolute,
            constant_string_identifiers=constant_string_identifiers,
        ):
            constant_string_identifiers.add(assignment.group(1).casefold())
    if not (
        init_index
        < while_index
        < append_index
        < increment_index
        < wend_index
        < return_index
    ):
        return None, "invalid_profile_order"
    return (
        _SliceProfile(
            function_name=procedure.name,
            parameter=procedure.parameter,
            start=start,
            tail=tail,
            step=step,
            width=width,
            width_resolution=width_resolution,
        ),
        None,
    )


def _decode_vb_string(value: str) -> str:
    return value.replace('""', '"')


def _recover_slice(
    literal: str,
    profile: _SliceProfile,
    *,
    limits: VbscriptConstantSinkLimits,
    budget: _Budget,
) -> str | None:
    if len(literal) > limits.max_literal_characters:
        raise _LimitExceeded("max_literal_characters")
    last_position = len(literal) - profile.tail
    if profile.start < 1 or last_position < profile.start:
        return None
    iteration_count = ((last_position - profile.start) // profile.step) + 1
    # ``Mid``は末尾で短くなる場合があるが、保守的上限で先にmemoryを拘束する。
    if iteration_count > limits.max_work_units // profile.width:
        raise _LimitExceeded("max_work_units")
    output: list[str] = []
    position = profile.start
    while position <= last_position:
        start = position - 1
        chunk = literal[start : start + profile.width]
        budget.work(len(chunk))
        output.append(chunk)
        position += profile.step
    return "".join(output)


def _validate_output(
    value: str,
    *,
    budget: _Budget,
) -> tuple[bool, dict[str, object]]:
    if not value or "\x00" in value:
        return False, {}
    printable = sum(
        character.isprintable() or character in "\r\n\t" for character in value
    )
    if printable / len(value) < 0.98:
        return False, {}
    tokens: list[str] = []
    position = 0
    parenthesis_depth = 0
    while position < len(value):
        if value[position].isspace():
            position += 1
            continue
        match = _OUTPUT_TOKEN_RE.match(value, position)
        if match is None:
            return False, {}
        token = match.group(0)
        tokens.append(token)
        if token == "(":
            parenthesis_depth += 1
        elif token == ")":
            parenthesis_depth -= 1
            if parenthesis_depth < 0:
                return False, {}
        position = match.end()
        budget.work(1)
    if parenthesis_depth or len(tokens) < 5:
        return False, {}
    identifier_count = sum(bool(_IDENTIFIER_RE.fullmatch(token)) for token in tokens)
    if identifier_count < 3 or "=" not in tokens:
        return False, {}
    statement_count = len(_scan_output_statements(value))
    if statement_count < 1:
        return False, {}
    return (
        True,
        {
            "format": "bounded_vbscript_token_stream",
            "token_count": len(tokens),
            "statement_count": statement_count,
            "printable_ratio": round(printable / len(value), 6),
        },
    )


def _scan_output_statements(value: str) -> list[str]:
    statements: list[str] = []
    for line in value.splitlines() or [value]:
        parts = _split_line(line)
        if parts is None or (not parts and line.strip()):
            return []
        statements.extend(parts)
    return statements


def recover_vbscript_constant_sinks(
    data: bytes,
    *,
    limits: VbscriptConstantSinkLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """strictな固定slice profileの直接 ``Execute`` 引数だけを復元する。"""

    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    if len(data) > limits.max_input_bytes:
        return _base_report(limits, status="input_limit_exceeded"), []
    decoded = _decode_source(data)
    if decoded is None:
        return _base_report(limits, status="text_decode_failed"), []
    text, encoding = decoded
    budget = _Budget(limits)
    rejection_counts: Counter[str] = Counter()
    try:
        statements = _scan_statements(text, limits=limits, budget=budget)
        partitioned = _partition_procedures(statements, limits=limits)
        if partitioned is None:
            report = _base_report(
                limits, status="ambiguous_procedure_structure", budget=budget
            )
            report["encoding"] = encoding
            return report, []
        top_level, procedures = partitioned
        external_integer_constants = _resolve_repeated_character_integer_constants(
            top_level,
            limits=limits,
        )
        functions: dict[str, list[_Procedure]] = {}
        for procedure in procedures:
            if procedure.kind == "function":
                functions.setdefault(procedure.name.casefold(), []).append(procedure)

        direct_sinks: list[tuple[_Statement, str]] = []
        compound_sink_count = 0
        for statement in top_level:
            if not _EXECUTE_PREFIX_RE.match(statement.text):
                continue
            direct = _DIRECT_EXECUTE_RE.fullmatch(statement.text)
            if direct is None:
                compound_sink_count += 1
                rejection_counts["non_direct_execute_argument"] += 1
                continue
            direct_sinks.append((statement, direct.group(1) or direct.group(2)))
            if len(direct_sinks) > limits.max_sinks:
                raise _LimitExceeded("max_sinks")

        sink_name_counts = Counter(name.casefold() for _, name in direct_sinks)
        assignments: dict[str, list[_Statement]] = {}
        for statement in top_level:
            assignment = _ASSIGNMENT_RE.fullmatch(statement.text)
            if assignment is not None:
                assignments.setdefault(assignment.group(1).casefold(), []).append(
                    statement
                )

        profile_cache: dict[str, tuple[_SliceProfile | None, str | None]] = {}
        artifacts: list[tuple[str, bytes]] = []
        candidates: list[dict[str, object]] = []
        seen_outputs: set[str] = set()
        total_output_bytes = 0
        for sink_statement, sink_name in direct_sinks:
            budget.attempt()
            sink_key = sink_name.casefold()
            if sink_name_counts[sink_key] != 1:
                rejection_counts["repeated_direct_sink"] += 1
                continue
            sink_assignments = assignments.get(sink_key, [])
            if len(sink_assignments) != 1:
                rejection_counts["ambiguous_sink_assignment"] += 1
                continue
            assignment = _ASSIGNMENT_RE.fullmatch(sink_assignments[0].text)
            if assignment is None:
                rejection_counts["invalid_sink_assignment"] += 1
                continue
            call = _CALL_LITERAL_RE.fullmatch(assignment.group(2).strip())
            if call is None:
                rejection_counts["nonliteral_function_argument"] += 1
                continue
            function_name = call.group(1)
            function_key = function_name.casefold()
            definitions = functions.get(function_key, [])
            if len(definitions) != 1:
                rejection_counts["ambiguous_function_definition"] += 1
                continue
            if function_key not in profile_cache:
                profile_cache[function_key] = _match_slice_profile(
                    definitions[0],
                    limits=limits,
                    budget=budget,
                    external_integer_constants=external_integer_constants,
                )
            profile, profile_rejection = profile_cache[function_key]
            if profile is None:
                rejection_counts[profile_rejection or "profile_rejected"] += 1
                continue
            literal = _decode_vb_string(call.group(2))
            recovered = _recover_slice(
                literal,
                profile,
                limits=limits,
                budget=budget,
            )
            if recovered is None:
                rejection_counts["empty_inverse_slice"] += 1
                continue
            output = recovered.encode("utf-8")
            valid, format_report = _validate_output(recovered, budget=budget)
            if not valid:
                rejection_counts["output_format_rejected"] += 1
                continue
            digest = _sha256(output)
            if digest in seen_outputs:
                rejection_counts["duplicate_output"] += 1
                continue
            if total_output_bytes > limits.max_output_bytes - len(output):
                raise _LimitExceeded("max_output_bytes")
            if len(candidates) >= limits.max_candidate_count:
                raise _LimitExceeded("max_candidate_count")
            total_output_bytes += len(output)
            seen_outputs.add(digest)
            candidates.append(
                {
                    "sink_line": sink_statement.line,
                    "assignment_line": sink_assignments[0].line,
                    "function_line": definitions[0].line,
                    "literal_size": len(literal),
                    "slice": {
                        "index_base": 1,
                        "start": profile.start,
                        "tail_trim": profile.tail,
                        "step": profile.step,
                        "width": profile.width,
                        "width_resolution": profile.width_resolution,
                    },
                    "output_size": len(output),
                    "output_sha256": digest,
                    "output_validation": format_report,
                }
            )
            artifacts.append(
                (f"vbscript-constant-direct-execute-{len(artifacts) + 1:03d}", output)
            )
    except _LexicalRejected as error:
        report = _base_report(
            limits,
            status="ambiguous_lexical_structure",
            budget=budget,
        )
        report.update(
            {
                "encoding": encoding,
                "lexical_rejection": str(error),
                "candidate_set_complete": False,
                "rejections": dict(sorted(rejection_counts.items())),
            }
        )
        return report, []
    except _LimitExceeded as error:
        report = _base_report(limits, status="limit_exceeded", budget=budget)
        report.update(
            {
                "encoding": encoding,
                "limit": error.limit_name,
                "candidate_set_complete": False,
                "rejections": dict(sorted(rejection_counts.items())),
            }
        )
        return report, []

    status = "artifacts_recovered" if artifacts else "pattern_not_found"
    if not artifacts and rejection_counts:
        status = "candidates_rejected"
    report = _base_report(limits, status=status, budget=budget)
    report.update(
        {
            "encoding": encoding,
            "statement_count": len(statements),
            "function_count": len(functions),
            "direct_sink_count": len(direct_sinks),
            "compound_sink_count": compound_sink_count,
            "candidate_count": len(candidates),
            "candidate_set_complete": True,
            "candidates": candidates,
            "rejections": dict(sorted(rejection_counts.items())),
            "evaluation_boundary": {
                "operations_used": [
                    "string_literal",
                    "ampersand_literal_concatenation_validation",
                    "constant_integer_arithmetic",
                    "explicit_sink_argument_inverse_slice",
                ],
                "general_expression_evaluation": False,
                "dynamic_call_evaluation": False,
            },
        }
    )
    return report, artifacts
