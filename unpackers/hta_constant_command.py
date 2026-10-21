"""HTAの限定定数dataflowを静的復元する。

一般VBScript/JScript evaluatorではない。VBScriptでは明示的な ``script``
block、定数文字列、ASCII範囲の ``Chr`` / ``ChrW``、文字列連結、単一代入、
同一receiverの ``ExpandEnvironmentStrings("%COMSPEC%")`` と ``Run`` だけを扱う。
JScriptでは明示的なbyte配列を ``bin.hex`` で ``ADODB.Stream`` へ書き、
``SaveToFile`` 後に ``Run`` する限定profileだけを扱う。巨大HTAは全体を
text化せず、script blockとsink側sliceを先に切り出し、配列tokenを一度ずつ
上限付きでdecodeする。COM object、command、PowerShell、script、復元payloadは
一切実行しない。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from unpackers.bounded_pe_scan import inspect_structural_pe_extent

IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
PROFILE_NAME = "hta-vbscript-constant-wscript-shell-run-v1"
JSCRIPT_BYTE_ARRAY_PROFILE_NAME = "hta-jscript-binhex-byte-array-dropper-v1"

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

    max_input_bytes: int = 16 * 1024 * 1024
    max_script_blocks: int = 16
    max_script_tag_characters: int = 4096
    max_script_body_characters: int = 16 * 1024 * 1024
    max_statements: int = 20_000
    max_expression_characters: int = 2 * 1024 * 1024
    max_terms: int = 262_144
    max_output_bytes: int = 2 * 1024 * 1024
    max_byte_array_terms: int = 2 * 1024 * 1024
    max_control_slice_bytes: int = 1024 * 1024
    max_work_units: int = 32 * 1024 * 1024


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


@dataclass(frozen=True)
class _ScriptBlock:
    """原本bytes上のscript block範囲。body全体は複製しない。"""

    index: int
    attributes: str
    body_start: int
    body_end: int
    encoding: str


@dataclass(frozen=True)
class _JSByteArrayAssignment:
    """comment/string外で確認したJScript byte配列代入。"""

    name: str
    values_start: int


def _decode_fragment(data: bytes, encoding: str) -> str | None:
    """bounded fragmentだけをstrict decodeする。"""

    if encoding in {"utf-16-le", "utf-16-be"}:
        if len(data) % 2:
            return None
        try:
            return data.decode(encoding).removeprefix("\ufeff")
        except UnicodeDecodeError:
            return None
    for candidate in ("utf-8-sig", "cp1252"):
        try:
            text = data.decode(candidate)
        except UnicodeDecodeError:
            continue
        if "\x00" not in text:
            return text
    return None


def _markup_encoding(data: bytes) -> str | None:
    """script tagの一意なbyte encodingを全入力の複製なしで選ぶ。"""

    if data.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return "utf-16-be"
    _, lexical_encoding = _hta_profile_signal(data)
    if lexical_encoding in {"utf-16-le", "utf-16-be"}:
        return lexical_encoding
    candidates: list[str] = []
    if re.search(rb"(?i)<script(?:[\t\r\n />])", data):
        candidates.append("single-byte")
    for encoding in ("utf-16-le", "utf-16-be"):
        marker = _encoded_pattern("<script", encoding)
        if marker.search(data):
            candidates.append(encoding)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _encoded_pattern(value: str, encoding: str) -> re.Pattern[bytes]:
    if encoding == "single-byte":
        return re.compile(re.escape(value.encode("ascii")), re.IGNORECASE)
    fragments: list[bytes] = []
    for character in value:
        if character.isascii() and character.isalpha():
            lower = re.escape(character.lower().encode(encoding))
            upper = re.escape(character.upper().encode(encoding))
            fragments.append(b"(?:" + lower + b"|" + upper + b")")
        else:
            fragments.append(re.escape(character.encode(encoding)))
    return re.compile(b"".join(fragments))


def _encoded_width(encoding: str) -> int:
    return 2 if encoding in {"utf-16-le", "utf-16-be"} else 1


def _find_tag_end(
    data: bytes,
    start: int,
    *,
    encoding: str,
    maximum_characters: int,
) -> int | None:
    width = _encoded_width(encoding)
    marker = ">".encode("ascii" if encoding == "single-byte" else encoding)
    stop = min(len(data), start + maximum_characters * width)
    position = data.find(marker, start, stop)
    return None if position < 0 else position + width


def _next_active_script_opener(
    data: bytes,
    position: int,
    *,
    encoding: str,
) -> re.Match[bytes] | None:
    """HTML data stateの ``script`` openerだけを一回の順方向走査で返す。"""

    width = _encoded_width(encoding)
    opener = _encoded_pattern("<script", encoding)
    comment_opener = _encoded_pattern("<!--", encoding)
    comment_closer = _encoded_pattern("-->", encoding)
    less_than = "<".encode("ascii" if encoding == "single-byte" else encoding)
    greater_than = ">".encode("ascii" if encoding == "single-byte" else encoding)
    single_quote = "'".encode("ascii" if encoding == "single-byte" else encoding)
    double_quote = '"'.encode("ascii" if encoding == "single-byte" else encoding)
    while position < len(data):
        comment = comment_opener.match(data, position)
        if comment is not None:
            end = comment_closer.search(data, comment.end())
            if end is None:
                return None
            position = end.end()
            continue
        script = opener.match(data, position)
        if script is not None:
            return script
        if data[position : position + width] != less_than:
            position += width
            continue
        next_unit = _decode_fragment(
            data[position + width : position + 2 * width],
            "ascii" if encoding == "single-byte" else encoding,
        )
        if next_unit is None or not (
            next_unit.isascii()
            and (next_unit.isalpha() or next_unit in {"!", "/", "?"})
        ):
            position += width
            continue
        cursor = position + width
        quote: bytes | None = None
        while cursor < len(data):
            unit = data[cursor : cursor + width]
            if quote is not None:
                if unit == quote:
                    quote = None
            elif unit in {single_quote, double_quote}:
                quote = unit
            elif unit == greater_than:
                cursor += width
                break
            cursor += width
        position = cursor
    return None


def _scan_script_blocks(
    data: bytes,
    *,
    encoding: str,
    limits: HtaConstantCommandLimits,
) -> list[_ScriptBlock]:
    """HTMLをrenderせずscript tagを順方向に走査する。"""

    closer = _encoded_pattern("</script", encoding)
    blocks: list[_ScriptBlock] = []
    position = 0
    while True:
        match = _next_active_script_opener(data, position, encoding=encoding)
        if match is None:
            break
        width = _encoded_width(encoding)
        boundary = _decode_fragment(
            data[match.end() : match.end() + width],
            "ascii" if encoding == "single-byte" else encoding,
        )
        if boundary is None or boundary not in {" ", "\t", "\r", "\n", ">"}:
            position = match.end()
            continue
        open_end = _find_tag_end(
            data,
            match.end(),
            encoding=encoding,
            maximum_characters=limits.max_script_tag_characters,
        )
        if open_end is None:
            raise _Rejected("unbalanced_script_blocks")
        actual_encoding = "ascii" if encoding == "single-byte" else encoding
        attributes = _decode_fragment(
            data[match.end() : open_end - _encoded_width(encoding)],
            actual_encoding,
        )
        if attributes is None:
            raise _Rejected("script_attributes_decode_failed")
        close_match = closer.search(data, open_end)
        if close_match is None:
            raise _Rejected("unbalanced_script_blocks")
        nested = _encoded_pattern("<script", encoding).search(
            data, open_end, close_match.start()
        )
        if nested is not None:
            raise _Rejected("unbalanced_script_blocks")
        close_end = _find_tag_end(
            data,
            close_match.end(),
            encoding=encoding,
            maximum_characters=64,
        )
        if close_end is None:
            raise _Rejected("unbalanced_script_blocks")
        closing = _decode_fragment(
            data[close_match.start() : close_end], actual_encoding
        )
        if closing is None or re.fullmatch(r"(?is)</script\s*>", closing) is None:
            raise _Rejected("invalid_script_close_tag")
        blocks.append(
            _ScriptBlock(
                index=len(blocks) + 1,
                attributes=attributes,
                body_start=open_end,
                body_end=close_match.start(),
                encoding=actual_encoding,
            )
        )
        if len(blocks) > limits.max_script_blocks:
            raise _LimitExceeded("max_script_blocks")
        position = close_end
    return blocks


def _is_javascript_attributes(attributes: dict[str, str]) -> bool:
    if "src" in attributes:
        return False
    language = attributes.get("language", "").strip().casefold()
    media_type = attributes.get("type", "").strip().casefold()
    return language in {"javascript", "jscript", "js"} or media_type in {
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
    }


def _is_js_identifier_start(value: int) -> bool:
    return value in {0x24, 0x5F} or 0x41 <= value <= 0x5A or 0x61 <= value <= 0x7A


def _is_js_identifier_part(value: int) -> bool:
    return _is_js_identifier_start(value) or 0x30 <= value <= 0x39


def _skip_js_quoted_bytes(body: memoryview, index: int) -> int:
    quote = body[index]
    index += 1
    while index < len(body):
        value = body[index]
        if value == quote:
            return index + 1
        if value in {0x0A, 0x0D}:
            raise _Rejected("unterminated_jscript_string")
        if value == 0x5C:
            index += 2
        else:
            index += 1
    raise _Rejected("unterminated_jscript_string")


def _skip_js_lexical_space_and_comments(body: memoryview, index: int) -> int:
    while index < len(body):
        value = body[index]
        if value in b" \t\r\n":
            index += 1
            continue
        if value == 0x2F and index + 1 < len(body) and body[index + 1] == 0x2F:
            newline = index + 2
            while newline < len(body) and body[newline] not in b"\r\n":
                newline += 1
            index = newline
            continue
        if value == 0x2F and index + 1 < len(body) and body[index + 1] == 0x2A:
            end = index + 2
            while end + 1 < len(body) and not (
                body[end] == 0x2A and body[end + 1] == 0x2F
            ):
                end += 1
            if end + 1 >= len(body):
                raise _Rejected("unterminated_jscript_comment")
            index = end + 2
            continue
        break
    return index


def _find_js_byte_array_assignments(
    body: memoryview,
    *,
    budget: _Budget,
) -> list[_JSByteArrayAssignment]:
    """comment/string/regexの外にある直接の配列代入だけを一回走査で探す。"""

    budget.work(len(body))
    assignments: list[_JSByteArrayAssignment] = []
    index = 0
    while index < len(body):
        value = body[index]
        if value in {0x22, 0x27}:
            index = _skip_js_quoted_bytes(body, index)
            continue
        if value == 0x60:
            raise _Rejected("unsupported_jscript_template_literal")
        if value == 0x2F:
            if index + 1 < len(body) and body[index + 1] in {0x2F, 0x2A}:
                index = _skip_js_lexical_space_and_comments(body, index)
            else:
                raise _Rejected("unsupported_jscript_lexical_slash")
            continue
        if value == 0x3C and body[index : index + 4].tobytes() == b"<!--":
            newline = index + 4
            while newline < len(body) and body[newline] not in b"\r\n":
                newline += 1
            index = newline
            continue
        if not _is_js_identifier_start(value):
            index += 1
            continue
        word_start = index
        index += 1
        while index < len(body) and _is_js_identifier_part(body[index]):
            index += 1
        keyword = bytes(body[word_start:index]).lower()
        if keyword not in {b"var", b"let", b"const"}:
            continue
        cursor = _skip_js_lexical_space_and_comments(body, index)
        if cursor >= len(body) or not _is_js_identifier_start(body[cursor]):
            continue
        name_start = cursor
        cursor += 1
        while cursor < len(body) and _is_js_identifier_part(body[cursor]):
            cursor += 1
        name = bytes(body[name_start:cursor]).decode("ascii")
        cursor = _skip_js_lexical_space_and_comments(body, cursor)
        if cursor >= len(body) or body[cursor] != 0x3D:
            continue
        cursor = _skip_js_lexical_space_and_comments(body, cursor + 1)
        if cursor >= len(body) or body[cursor] != 0x5B:
            continue
        assignments.append(_JSByteArrayAssignment(name, cursor + 1))
        if len(assignments) > 1:
            return assignments
        index = cursor + 1
    return assignments


def _skip_js_array_space_and_comments(
    body: memoryview,
    index: int,
    *,
    budget: _Budget,
) -> int:
    """byte配列内で許可するASCII空白とcommentだけを飛ばす。"""

    length = len(body)
    while index < length:
        value = body[index]
        if value in b" \t\r\n":
            budget.work(1)
            index += 1
            continue
        if value == 0x2F and index + 1 < length and body[index + 1] == 0x2F:
            end = index + 2
            while end < length and body[end] not in b"\r\n":
                end += 1
            budget.work(end - index)
            index = end
            continue
        if value == 0x2F and index + 1 < length and body[index + 1] == 0x2A:
            end = index + 2
            while end + 1 < length and not (
                body[end] == 0x2A and body[end + 1] == 0x2F
            ):
                end += 1
            if end + 1 >= length:
                raise _Rejected("unterminated_jscript_array_comment")
            end += 2
            budget.work(end - index)
            index = end
            continue
        break
    return index


def _decode_js_byte_array(
    body: memoryview,
    start: int,
    *,
    limits: HtaConstantCommandLimits,
    budget: _Budget,
) -> tuple[bytes, int, int]:
    """numeric arrayをlist化せず1 tokenずつbyte列へ変換する。"""

    output = bytearray()
    index = start
    expecting_value = True
    term_count = 0
    while True:
        index = _skip_js_array_space_and_comments(body, index, budget=budget)
        if index >= len(body):
            raise _Rejected("unterminated_jscript_byte_array")
        if body[index] == 0x5D:  # ]
            if not output:
                raise _Rejected("empty_jscript_byte_array")
            budget.work(1)
            return bytes(output), index + 1, term_count
        if not expecting_value:
            if body[index] != 0x2C:  # ,
                raise _Rejected("invalid_jscript_byte_array_separator")
            budget.work(1)
            index += 1
            expecting_value = True
            continue
        token_start = index
        base = 10
        if (
            index + 2 <= len(body)
            and body[index] == 0x30
            and body[index + 1] in {0x58, 0x78}
        ):
            base = 16
            index += 2
            digits_start = index
            while index < len(body) and (
                0x30 <= body[index] <= 0x39
                or 0x41 <= body[index] <= 0x46
                or 0x61 <= body[index] <= 0x66
            ):
                index += 1
            if index == digits_start:
                raise _Rejected("invalid_jscript_hex_byte")
        else:
            while index < len(body) and 0x30 <= body[index] <= 0x39:
                index += 1
            if index == token_start:
                raise _Rejected("unsupported_jscript_byte_expression")
        token = bytes(body[token_start:index])
        try:
            value = int(token, base)
        except ValueError as exc:
            raise _Rejected("invalid_jscript_byte") from exc
        if not 0 <= value <= 0xFF:
            raise _Rejected("jscript_byte_out_of_range")
        output.append(value)
        term_count += 1
        budget.work(index - token_start)
        if term_count > limits.max_byte_array_terms:
            raise _LimitExceeded("max_byte_array_terms")
        if len(output) > limits.max_output_bytes:
            raise _LimitExceeded("max_output_bytes")
        expecting_value = False


def _valid_pe_payload(payload: bytes) -> bool:
    extent = inspect_structural_pe_extent(payload, max_extent=len(payload))
    return extent.extent is not None


@dataclass(frozen=True)
class _JSToken:
    """commentを除外して得た限定JScript token。"""

    kind: str
    value: str
    offset: int


@dataclass(frozen=True)
class _JSCall:
    receiver: str
    method: str
    arguments: tuple[tuple[_JSToken, ...], ...]
    start: int
    end: int


def _decode_js_string(value: str, start: int) -> tuple[str, int]:
    """JScript文字列を実行せず、限定escapeだけを定数復元する。"""

    quote = value[start]
    index = start + 1
    output: list[str] = []
    simple_escapes = {
        "\\": "\\",
        "'": "'",
        '"': '"',
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
        "v": "\v",
    }
    while index < len(value):
        character = value[index]
        if character == quote:
            return "".join(output), index + 1
        if character in "\r\n":
            raise _Rejected("unterminated_jscript_string")
        if character != "\\":
            output.append(character)
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise _Rejected("unterminated_jscript_string")
        escaped = value[index]
        if escaped in simple_escapes:
            output.append(simple_escapes[escaped])
            index += 1
            continue
        if escaped in {"x", "u"}:
            width = 2 if escaped == "x" else 4
            digits = value[index + 1 : index + 1 + width]
            if len(digits) != width or re.fullmatch(r"[0-9A-Fa-f]+", digits) is None:
                raise _Rejected("unsupported_jscript_string_escape")
            output.append(chr(int(digits, 16)))
            index += width + 1
            continue
        raise _Rejected("unsupported_jscript_string_escape")
    raise _Rejected("unterminated_jscript_string")


def _tokenize_jscript(
    value: str,
    *,
    limits: HtaConstantCommandLimits,
    budget: _Budget,
) -> list[_JSToken]:
    """comment/string境界を保持する有界なJScript lexer。"""

    budget.work(len(value))
    tokens: list[_JSToken] = []
    index = 0
    two_character_symbols = {
        "++",
        "--",
        "+=",
        "-=",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
    }
    while index < len(value):
        character = value[index]
        if character.isspace():
            index += 1
            continue
        if value.startswith("//", index):
            newline = value.find("\n", index + 2)
            index = len(value) if newline < 0 else newline + 1
            continue
        if value.startswith("/*", index):
            end = value.find("*/", index + 2)
            if end < 0:
                raise _Rejected("unterminated_jscript_comment")
            index = end + 2
            continue
        offset = index
        if character in {'"', "'"}:
            decoded, index = _decode_js_string(value, index)
            tokens.append(_JSToken("string", decoded, offset))
        elif character.isascii() and (character.isalpha() or character in "_$"):
            index += 1
            while (
                index < len(value)
                and value[index].isascii()
                and (value[index].isalnum() or value[index] in "_$")
            ):
                index += 1
            tokens.append(_JSToken("identifier", value[offset:index], offset))
        elif character.isascii() and character.isdigit():
            index += 1
            while (
                index < len(value)
                and value[index].isascii()
                and (value[index].isalnum() or value[index] in "xX")
            ):
                index += 1
            tokens.append(_JSToken("number", value[offset:index], offset))
        else:
            symbol = value[index : index + 2]
            if symbol in two_character_symbols:
                index += 2
            else:
                symbol = character
                index += 1
            tokens.append(_JSToken("symbol", symbol, offset))
        if len(tokens) > limits.max_terms:
            raise _LimitExceeded("max_terms")
    return tokens


def _token_is(token: _JSToken, value: str, *, casefold: bool = False) -> bool:
    if casefold:
        return token.value.casefold() == value.casefold()
    return token.value == value


def _symbol_pairs(tokens: list[_JSToken], *, budget: _Budget) -> dict[int, int]:
    """括弧対応を一回のstack走査で求め、反復全走査を避ける。"""

    openers = {"(": ")", "[": "]", "{": "}"}
    closers = set(openers.values())
    stack: list[tuple[str, int]] = []
    pairs: dict[int, int] = {}
    for index, token in enumerate(tokens):
        budget.work(1)
        if token.value in openers:
            stack.append((openers[token.value], index))
        elif token.value in closers:
            if not stack or stack[-1][0] != token.value:
                raise _Rejected("unbalanced_jscript_symbols")
            _, start = stack.pop()
            pairs[start] = index
    if stack:
        raise _Rejected("unbalanced_jscript_symbols")
    return pairs


def _split_js_arguments(
    tokens: list[_JSToken], start: int, end: int, *, budget: _Budget
) -> tuple[tuple[_JSToken, ...], ...] | None:
    if start == end:
        return ()
    arguments: list[tuple[_JSToken, ...]] = []
    item_start = start
    depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    closers = set(pairs.values())
    stack: list[str] = []
    for index in range(start, end):
        budget.work(1)
        value = tokens[index].value
        if value in pairs:
            stack.append(pairs[value])
            depth += 1
        elif value in closers:
            if not stack or stack[-1] != value:
                return None
            stack.pop()
            depth -= 1
        elif value == "," and depth == 0:
            if index == item_start:
                return None
            arguments.append(tuple(tokens[item_start:index]))
            item_start = index + 1
    if stack or item_start == end:
        return None
    arguments.append(tuple(tokens[item_start:end]))
    return tuple(arguments)


def _js_calls(
    tokens: list[_JSToken], pairs: dict[int, int], *, budget: _Budget
) -> list[_JSCall]:
    calls: list[_JSCall] = []
    for index in range(len(tokens) - 3):
        budget.work(1)
        if (
            tokens[index].kind != "identifier"
            or not _token_is(tokens[index + 1], ".")
            or tokens[index + 2].kind != "identifier"
            or not _token_is(tokens[index + 3], "(")
        ):
            continue
        end = pairs.get(index + 3)
        if end is None:
            raise _Rejected("unbalanced_jscript_call")
        arguments = _split_js_arguments(tokens, index + 4, end, budget=budget)
        if arguments is None:
            raise _Rejected("invalid_jscript_call_arguments")
        calls.append(
            _JSCall(
                receiver=tokens[index].value,
                method=tokens[index + 2].value,
                arguments=arguments,
                start=index,
                end=end + 1,
            )
        )
    return calls


def _find_activex_assignment(
    tokens: list[_JSToken], progid: str
) -> tuple[str, int] | None:
    matches: list[tuple[str, int]] = []
    for index in range(len(tokens) - 6):
        cursor = index
        if tokens[cursor].kind == "identifier" and tokens[cursor].value.casefold() in {
            "var",
            "let",
            "const",
        }:
            cursor += 1
        if cursor + 5 >= len(tokens):
            continue
        if (
            tokens[cursor].kind == "identifier"
            and _token_is(tokens[cursor + 1], "=")
            and _token_is(tokens[cursor + 2], "new", casefold=True)
            and _token_is(tokens[cursor + 3], "ActiveXObject", casefold=True)
            and _token_is(tokens[cursor + 4], "(")
            and tokens[cursor + 5].kind == "string"
            and tokens[cursor + 5].value.casefold() == progid.casefold()
            and cursor + 6 < len(tokens)
            and _token_is(tokens[cursor + 6], ")")
            and _simple_assignment_ends(tokens, cursor + 7)
        ):
            match = (tokens[cursor].value, cursor)
            if match in matches:
                continue
            matches.append(match)
            if len(matches) > 1:
                return None
    return matches[0] if matches else None


def _find_array_hex_flow(
    tokens: list[_JSToken],
    array_name: str,
    pairs: dict[int, int],
    *,
    budget: _Budget,
) -> tuple[str, int, int] | None:
    """同一array/indexからhex accumulatorまでの限定loopを相関する。"""

    for loop_start, token in enumerate(tokens):
        budget.work(1)
        if not _token_is(token, "for", casefold=True):
            continue
        if loop_start + 1 >= len(tokens) or not _token_is(tokens[loop_start + 1], "("):
            continue
        header_end = pairs.get(loop_start + 1)
        if header_end is None or header_end + 1 >= len(tokens):
            continue
        if not _token_is(tokens[header_end + 1], "{"):
            continue
        body_end = pairs.get(header_end + 1)
        if body_end is None:
            continue
        header = tokens[loop_start + 2 : header_end]
        body = tokens[header_end + 2 : body_end]
        budget.work(len(header) + len(body))
        length_positions = [
            index
            for index in range(len(header) - 2)
            if header[index].kind == "identifier"
            and header[index].value == array_name
            and _token_is(header[index + 1], ".")
            and _token_is(header[index + 2], "length", casefold=True)
        ]
        if len(length_positions) != 1:
            continue
        item_name: str | None = None
        item_assignment_position: int | None = None
        index_name: str | None = None
        for cursor in range(len(body) - 10):
            item_cursor = cursor
            if body[item_cursor].kind == "identifier" and body[
                item_cursor
            ].value.casefold() in {"var", "let", "const"}:
                item_cursor += 1
            if item_cursor + 9 >= len(body):
                continue
            if (
                body[item_cursor].kind == "identifier"
                and _token_is(body[item_cursor + 1], "=")
                and body[item_cursor + 2].kind == "identifier"
                and body[item_cursor + 2].value == array_name
                and _token_is(body[item_cursor + 3], "[")
                and body[item_cursor + 4].kind == "identifier"
                and _token_is(body[item_cursor + 5], "]")
                and _token_is(body[item_cursor + 6], ".")
                and _token_is(body[item_cursor + 7], "toString", casefold=True)
                and _token_is(body[item_cursor + 8], "(")
                and _token_is(body[item_cursor + 9], "16")
                and item_cursor + 10 < len(body)
                and _token_is(body[item_cursor + 10], ")")
                and _simple_assignment_ends(body, item_cursor + 11)
            ):
                item_name = body[item_cursor].value
                item_assignment_position = item_cursor
                index_name = body[item_cursor + 4].value
                break
        if item_name is None or item_assignment_position is None or index_name is None:
            continue
        item_assignments = _direct_assignment_positions(body, item_name)
        if not item_assignments or item_assignments[0] != item_assignment_position:
            continue
        if len(item_assignments) > 2:
            continue
        if len(item_assignments) == 2:
            padding = item_assignments[1]
            if not (
                padding + 4 < len(body)
                and body[padding + 2].kind == "string"
                and body[padding + 2].value == "0"
                and _token_is(body[padding + 3], "+")
                and body[padding + 4].kind == "identifier"
                and body[padding + 4].value == item_name
                and _simple_assignment_ends(body, padding + 5)
            ):
                continue
        if len(item_assignments) != len(set(item_assignments)):
            continue
        if not any(
            header[index].kind == "identifier"
            and header[index].value == index_name
            and index + 1 < len(header)
            and _token_is(header[index + 1], "++")
            for index in range(len(header))
        ):
            continue
        accumulator: str | None = None
        accumulator_position: int | None = None
        for cursor in range(loop_start - 1, -1, -1):
            budget.work(1)
            if tokens[cursor].kind != "string" or tokens[cursor].value != "":
                continue
            if cursor < 2 or not _token_is(tokens[cursor - 1], "="):
                continue
            if not _simple_assignment_ends(tokens, cursor + 1):
                continue
            name_index = cursor - 2
            if tokens[name_index].kind != "identifier":
                continue
            accumulator = tokens[name_index].value
            accumulator_position = name_index
            break
        if accumulator is None or accumulator_position is None:
            continue
        if not any(
            body[index].kind == "identifier"
            and body[index].value == accumulator
            and index + 2 < len(body)
            and _token_is(body[index + 1], "+=")
            and body[index + 2].kind == "identifier"
            and body[index + 2].value == item_name
            for index in range(len(body))
        ):
            continue
        return accumulator, body_end, accumulator_position
    return None


def _find_method_assignment(
    tokens: list[_JSToken],
    *,
    receiver: str,
    method: str,
    literal_argument: str,
) -> tuple[str, int] | None:
    matches: list[tuple[str, int]] = []
    for index in range(len(tokens) - 7):
        cursor = index
        if tokens[cursor].kind == "identifier" and tokens[cursor].value.casefold() in {
            "var",
            "let",
            "const",
        }:
            cursor += 1
        if cursor + 7 >= len(tokens):
            continue
        if (
            tokens[cursor].kind == "identifier"
            and _token_is(tokens[cursor + 1], "=")
            and tokens[cursor + 2].kind == "identifier"
            and tokens[cursor + 2].value == receiver
            and _token_is(tokens[cursor + 3], ".")
            and _token_is(tokens[cursor + 4], method, casefold=True)
            and _token_is(tokens[cursor + 5], "(")
            and tokens[cursor + 6].kind == "string"
            and tokens[cursor + 6].value.casefold() == literal_argument.casefold()
            and _token_is(tokens[cursor + 7], ")")
            and _simple_assignment_ends(tokens, cursor + 8)
        ):
            match = (tokens[cursor].value, cursor)
            if match in matches:
                continue
            matches.append(match)
            if len(matches) > 1:
                return None
    return matches[0] if matches else None


def _find_property_assignment(
    tokens: list[_JSToken],
    *,
    receiver: str,
    property_name: str,
    rhs: tuple[tuple[str, str], ...],
) -> int | None:
    matches: list[int] = []
    for index in range(len(tokens) - 3 - len(rhs)):
        if (
            tokens[index].kind != "identifier"
            or tokens[index].value != receiver
            or not _token_is(tokens[index + 1], ".")
            or not _token_is(tokens[index + 2], property_name, casefold=True)
            or not _token_is(tokens[index + 3], "=")
        ):
            continue
        if all(
            tokens[index + 4 + offset].kind == kind
            and tokens[index + 4 + offset].value == value
            for offset, (kind, value) in enumerate(rhs)
        ) and _simple_assignment_ends(tokens, index + 4 + len(rhs)):
            matches.append(index)
            if len(matches) > 1:
                return None
    return matches[0] if matches else None


def _direct_assignment_positions(tokens: list[_JSToken], name: str) -> list[int]:
    """property代入を除く、追跡identifierへの直接代入位置を返す。"""

    return [
        index
        for index in range(len(tokens) - 1)
        if tokens[index].kind == "identifier"
        and tokens[index].value == name
        and _token_is(tokens[index + 1], "=")
    ]


def _simple_assignment_ends(tokens: list[_JSToken], index: int) -> bool:
    """限定profileの代入右辺が別の式へ継続していないことを確認する。"""

    return index >= len(tokens) or tokens[index].value in {";", "}"}


def _argument_key(argument: tuple[_JSToken, ...]) -> tuple[str, str] | None:
    if len(argument) != 1 or argument[0].kind not in {"identifier", "string"}:
        return None
    return argument[0].kind, argument[0].value


def _argument_is_defined_before(
    tokens: list[_JSToken], key: tuple[str, str], position: int
) -> bool:
    if key[0] == "string":
        return bool(key[1])
    assignments = _direct_assignment_positions(tokens, key[1])
    return len(assignments) == 1 and assignments[0] < position


def _jscript_sink_checks(
    variable: str,
    control: str,
    *,
    limits: HtaConstantCommandLimits,
    budget: _Budget,
) -> dict[str, bool]:
    """tokenized限定dataflowでarrayからRunまでを同一object/pathへ相関する。"""

    tokens = _tokenize_jscript(control, limits=limits, budget=budget)
    pairs = _symbol_pairs(tokens, budget=budget)
    flow = _find_array_hex_flow(tokens, variable, pairs, budget=budget)
    stream = _find_activex_assignment(tokens, "ADODB.Stream")
    xml = _find_activex_assignment(tokens, "MSXML2.DOMDocument")
    filesystem = _find_activex_assignment(tokens, "Scripting.FileSystemObject")
    shell = _find_activex_assignment(tokens, "WScript.Shell")
    if (
        flow is None
        or stream is None
        or xml is None
        or filesystem is None
        or shell is None
    ):
        raise _Rejected("jscript_sink_chain_incomplete")
    accumulator, flow_end, accumulator_position = flow
    stream_name, stream_position = stream
    xml_name, xml_position = xml
    filesystem_name, filesystem_position = filesystem
    shell_name, shell_position = shell
    node = _find_method_assignment(
        tokens,
        receiver=xml_name,
        method="createElement",
        literal_argument="bin",
    )
    if node is None:
        raise _Rejected("jscript_sink_chain_incomplete")
    node_name, node_position = node
    data_type_position = _find_property_assignment(
        tokens,
        receiver=node_name,
        property_name="dataType",
        rhs=(("string", "bin.hex"),),
    )
    text_position = _find_property_assignment(
        tokens,
        receiver=node_name,
        property_name="text",
        rhs=(("identifier", accumulator),),
    )
    stream_type_position = _find_property_assignment(
        tokens,
        receiver=stream_name,
        property_name="Type",
        rhs=(("number", "1"),),
    )
    calls = _js_calls(tokens, pairs, budget=budget)
    opens = [
        call
        for call in calls
        if call.receiver == stream_name
        and call.method.casefold() == "open"
        and not call.arguments
    ]
    writes = [
        call
        for call in calls
        if call.receiver == stream_name
        and call.method.casefold() == "write"
        and len(call.arguments) == 1
        and tuple((token.kind, token.value) for token in call.arguments[0])
        == (
            ("identifier", node_name),
            ("symbol", "."),
            ("identifier", "nodeTypedValue"),
        )
    ]
    saves = [
        call
        for call in calls
        if call.receiver == stream_name
        and call.method.casefold() == "savetofile"
        and len(call.arguments) == 2
        and _argument_key(call.arguments[0]) is not None
        and tuple((token.kind, token.value) for token in call.arguments[1])
        == (("number", "2"),)
    ]
    moves = [
        call
        for call in calls
        if call.receiver == filesystem_name
        and call.method.casefold() == "movefile"
        and len(call.arguments) == 2
        and _argument_key(call.arguments[0]) is not None
        and _argument_key(call.arguments[1]) is not None
    ]
    runs = [
        call
        for call in calls
        if call.receiver == shell_name
        and call.method.casefold() == "run"
        and len(call.arguments) >= 1
        and _argument_key(call.arguments[0]) is not None
    ]
    if not all(len(values) == 1 for values in (opens, writes, saves, moves, runs)):
        raise _Rejected("jscript_sink_chain_incomplete")
    if _direct_assignment_positions(tokens, stream_name) != [stream_position]:
        raise _Rejected("jscript_sink_chain_incomplete")
    if _direct_assignment_positions(tokens, xml_name) != [xml_position]:
        raise _Rejected("jscript_sink_chain_incomplete")
    if _direct_assignment_positions(tokens, filesystem_name) != [filesystem_position]:
        raise _Rejected("jscript_sink_chain_incomplete")
    if _direct_assignment_positions(tokens, shell_name) != [shell_position]:
        raise _Rejected("jscript_sink_chain_incomplete")
    if _direct_assignment_positions(tokens, node_name) != [node_position]:
        raise _Rejected("jscript_sink_chain_incomplete")
    if _direct_assignment_positions(tokens, accumulator) != [accumulator_position]:
        raise _Rejected("jscript_sink_chain_incomplete")
    if _direct_assignment_positions(tokens, variable):
        raise _Rejected("jscript_sink_chain_incomplete")
    open_call = opens[0]
    for write in writes:
        for save in saves:
            saved_path = _argument_key(save.arguments[0])
            if (
                save.start <= write.start
                or saved_path is None
                or not _argument_is_defined_before(tokens, saved_path, save.start)
            ):
                continue
            for move in moves:
                executable_path = _argument_key(move.arguments[1])
                if (
                    move.start <= save.start
                    or _argument_key(move.arguments[0]) != saved_path
                    or executable_path is None
                    or not _argument_is_defined_before(
                        tokens, executable_path, move.start
                    )
                ):
                    continue
                for run in runs:
                    if (
                        run.start <= move.start
                        or _argument_key(run.arguments[0]) != executable_path
                    ):
                        continue
                    positions = (
                        flow_end,
                        stream_position,
                        xml_position,
                        node_position,
                        data_type_position,
                        text_position,
                        stream_type_position,
                        open_call.start,
                        write.start,
                    )
                    if (
                        data_type_position is None
                        or text_position is None
                        or stream_type_position is None
                        or stream_position >= write.start
                        or xml_position >= node_position
                        or filesystem_position >= move.start
                        or shell_position >= run.start
                        or not (
                            node_position
                            < data_type_position
                            < text_position
                            < write.start
                            < save.start
                            < move.start
                            < run.start
                        )
                        or not (
                            stream_position
                            < stream_type_position
                            < open_call.start
                            < write.start
                        )
                        or flow_end >= text_position
                        or any(position is None for position in positions)
                    ):
                        continue
                    return {
                        "array_length_loop": True,
                        "array_index_hex": True,
                        "adodb_stream": True,
                        "stream_binary_type": True,
                        "stream_open": True,
                        "bin_hex": True,
                        "node_typed_value": True,
                        "stream_write": True,
                        "save_to_file": True,
                        "move_file": True,
                        "run_sink": True,
                    }
    raise _Rejected("jscript_sink_chain_incomplete")


def _analyze_jscript_block(
    body: memoryview,
    *,
    encoding: str,
    limits: HtaConstantCommandLimits,
    budget: _Budget,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """JScript byte arrayからterminal payloadとsink側sliceを復元する。"""

    if encoding != "ascii":
        raise _Rejected("unsupported_jscript_byte_array_encoding")
    assignments = _find_js_byte_array_assignments(body, budget=budget)
    if not assignments:
        raise _Rejected("jscript_byte_array_not_found")
    if len(assignments) != 1:
        raise _Rejected("ambiguous_jscript_byte_arrays")
    assignment = assignments[0]
    variable = assignment.name
    payload, array_end, term_count = _decode_js_byte_array(
        body,
        assignment.values_start,
        limits=limits,
        budget=budget,
    )
    if not _valid_pe_payload(payload):
        raise _Rejected("jscript_byte_array_not_pe")
    control_view = body[array_end:]
    if len(control_view) > limits.max_control_slice_bytes:
        raise _LimitExceeded("max_control_slice_bytes")
    control_bytes = bytes(control_view).strip()
    control = _decode_fragment(control_bytes, "ascii")
    if control is None:
        raise _Rejected("jscript_control_slice_decode_failed")
    checks = _jscript_sink_checks(variable, control, limits=limits, budget=budget)
    payload_digest = hashlib.sha256(payload).hexdigest()
    control_digest = hashlib.sha256(control_bytes).hexdigest()
    candidate = {
        "kind": "jscript_binhex_byte_array_dropper",
        "profile": JSCRIPT_BYTE_ARRAY_PROFILE_NAME,
        "byte_array_term_count": term_count,
        "payload_sha256": payload_digest,
        "payload_size": len(payload),
        "payload_format": "pe",
        "control_slice_sha256": control_digest,
        "control_slice_size": len(control_bytes),
        "sink_checks": checks,
        "artifact_count": 2,
    }
    return candidate, [
        ("hta-jscript-byte-array-payload.exe", payload),
        ("hta-jscript-control-slice.js", control_bytes),
    ]


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
    """限定HTA dataflowからcommand/payloadを検体非実行で復元する。"""

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
    encoding = _markup_encoding(data)
    if encoding is None:
        report = _base_report(limits, status="not_applicable")
        report.update(
            {
                "candidate_set_complete": True,
                "applicability": applicability,
            }
        )
        return report, []
    try:
        blocks = _scan_script_blocks(data, encoding=encoding, limits=limits)
    except _LimitExceeded as exc:
        report = _base_report(limits, status="limit_exceeded")
        report.update(
            {
                "encoding": encoding,
                "limit": str(exc),
                "applicability": applicability,
                "input_scan_bytes": len(data),
                "decoding_scope": "script_blocks_and_control_slices_only",
            }
        )
        return report, []
    except _Rejected as exc:
        report = _base_report(limits, status="profile_rejected")
        report.update(
            {
                "encoding": encoding,
                "rejections": {str(exc): 1},
                "applicability": applicability,
                "input_scan_bytes": len(data),
                "decoding_scope": "script_blocks_and_control_slices_only",
            }
        )
        return report, []
    if not blocks:
        report = _base_report(limits, status="not_applicable")
        report.update(
            {
                "encoding": encoding,
                "candidate_set_complete": True,
                "applicability": applicability,
                "input_scan_bytes": len(data),
                "decoding_scope": "script_blocks_and_control_slices_only",
            }
        )
        return report, []
    budget = _Budget(limits)
    candidates: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    rejections: Counter[str] = Counter()
    vbscript_blocks = 0
    jscript_blocks = 0
    profiled_script_body_bytes = 0
    try:
        for block in blocks:
            attributes = _parse_attributes(block.attributes)
            if attributes is None:
                # malformed/duplicate属性を持つscript blockを黙って除外すると、
                # 別blockだけでcandidate setをcompleteと誤認するためfail closed。
                rejections["invalid_script_attributes"] += 1
                continue
            is_vbscript = _is_vbscript_attributes(attributes)
            is_javascript = _is_javascript_attributes(attributes)
            if not is_vbscript and not is_javascript:
                continue
            body_size = block.body_end - block.body_start
            if body_size > limits.max_script_body_characters:
                raise _LimitExceeded("max_script_body_characters")
            body_view = memoryview(data)[block.body_start : block.body_end]
            if is_vbscript:
                vbscript_blocks += 1
                body = _decode_fragment(bytes(body_view), block.encoding)
                if body is None:
                    rejections["script_body_decode_failed"] += 1
                    continue
                profiled_script_body_bytes += body_size
                try:
                    candidate, recovered = _analyze_block(
                        body,
                        limits=limits,
                        budget=budget,
                    )
                except _Rejected as exc:
                    rejections[str(exc)] += 1
                    continue
                candidate = {
                    "kind": "vbscript_constant_run_command",
                    "profile": PROFILE_NAME,
                    **candidate,
                }
            else:
                jscript_blocks += 1
                profiled_script_body_bytes += body_size
                try:
                    candidate, recovered = _analyze_jscript_block(
                        body_view,
                        encoding=block.encoding,
                        limits=limits,
                        budget=budget,
                    )
                except _Rejected as exc:
                    if str(exc) == "jscript_byte_array_not_found":
                        continue
                    rejections[str(exc)] += 1
                    continue
            candidate = {"script_block_index": block.index, **candidate}
            candidates.append(candidate)
            artifacts.extend(recovered)
    except _LimitExceeded as exc:
        report = _base_report(limits, status="limit_exceeded")
        report.update(
            {
                "encoding": encoding,
                "limit": str(exc),
                "script_block_count": len(blocks),
                "vbscript_block_count": vbscript_blocks,
                "jscript_block_count": jscript_blocks,
                "rejections": dict(rejections),
                "work_units": budget.work_units,
                "input_scan_bytes": len(data),
                "profiled_script_body_bytes": profiled_script_body_bytes,
                "decoding_scope": "script_blocks_and_control_slices_only",
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
                "script_block_count": len(blocks),
                "vbscript_block_count": vbscript_blocks,
                "jscript_block_count": jscript_blocks,
                "candidate_set_complete": False,
                "candidate_count": len(candidates),
                "candidates": candidates,
                "rejections": dict(rejections),
                "work_units": budget.work_units,
                "input_scan_bytes": len(data),
                "profiled_script_body_bytes": profiled_script_body_bytes,
                "decoding_scope": "script_blocks_and_control_slices_only",
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
            "script_block_count": len(blocks),
            "vbscript_block_count": vbscript_blocks,
            "jscript_block_count": jscript_blocks,
            "candidate_set_complete": not bool(rejections),
            "candidate_count": len(candidates),
            "candidates": candidates,
            "rejections": dict(rejections),
            "work_units": budget.work_units,
            "input_scan_bytes": len(data),
            "profiled_script_body_bytes": profiled_script_body_bytes,
            "decoding_scope": "script_blocks_and_control_slices_only",
            "applicability": applicability,
        }
    )
    if not candidates and not rejections and vbscript_blocks == 0:
        report["status"] = "not_applicable"
        report["candidate_set_complete"] = True
    if candidates and rejections:
        report["status"] = "partial_profile_rejection"
        report["candidate_set_complete"] = False
        return report, []
    if not (vbscript_blocks or jscript_blocks) and rejections:
        report["status"] = "profile_rejected"
        report["candidate_set_complete"] = False
    return report, artifacts
