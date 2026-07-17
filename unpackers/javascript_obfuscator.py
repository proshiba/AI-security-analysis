"""Static JavaScript string-array deobfuscation without executing JavaScript."""

from __future__ import annotations

import ast
import base64
import json
import math
import re
from typing import Callable

_CUSTOM_BASE64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
_STANDARD_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_TRANSLATION = str.maketrans(_CUSTOM_BASE64, _STANDARD_BASE64)


def _safe_arithmetic(
    expression: str, parse_int: Callable[[int], float] | None = None
) -> float:
    """Evaluate only numeric literals, basic arithmetic, and optional p(integer)."""
    binary = {
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b,
        ast.Div: lambda a, b: a / b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.Mod: lambda a, b: a % b,
    }
    unary = {ast.UAdd: lambda value: value, ast.USub: lambda value: -value}

    def visit(node: ast.AST) -> float:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.BinOp) and type(node.op) in binary:
            return binary[type(node.op)](visit(node.left), visit(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in unary:
            return unary[type(node.op)](visit(node.operand))
        if (
            parse_int is not None
            and isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "p"
            and len(node.args) == 1
            and not node.keywords
        ):
            return float(parse_int(int(visit(node.args[0]))))
        raise ValueError("unsupported arithmetic syntax")

    return visit(ast.parse(expression, mode="eval"))


def _matching_bracket(text: str, start: int) -> int:
    """Find a JavaScript array's end while respecting quoted strings."""
    depth, quote, escaped = 0, None, False
    for index in range(start, len(text)):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unterminated JavaScript string array")


def _decode_literal(value: str) -> str:
    """Decode the alphabet-swapped Base64 routine used by the obfuscator."""
    translated = value.translate(_TRANSLATION)
    translated += "=" * (-len(translated) % 4)
    try:
        return base64.b64decode(translated, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""


def _javascript_parse_int(value: str) -> float:
    """Approximate parseInt for the generated decimal rotation sentinels."""
    match = re.match(r"^\s*([+-]?\d+)", value)
    return float(match.group(1)) if match else math.nan


def _fold_literal_additions(text: str) -> str:
    """Collapse adjacent quoted-string additions after decoder substitution."""
    quoted = r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
    sequence = re.compile(rf"{quoted}(?:\s*\+\s*{quoted})+")
    for _ in range(16):
        changed = False

        def replace(match: re.Match[str]) -> str:
            nonlocal changed
            values = re.findall(quoted, match.group())
            try:
                combined = "".join(ast.literal_eval(value) for value in values)
            except (ValueError, SyntaxError):
                return match.group()
            changed = True
            return json.dumps(combined, ensure_ascii=False)

        text = sequence.sub(replace, text)
        if not changed:
            break
    return text


def decode_script_text(data: bytes) -> str:
    """Decode common script encodings without interpreting script content."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="ignore")
    probe = data[: min(len(data), 4096)]
    if probe and probe.count(b"\x00") / len(probe) >= 0.2:
        even_nuls = probe[::2].count(0)
        odd_nuls = probe[1::2].count(0)
        encoding = "utf-16-be" if even_nuls > odd_nuls else "utf-16-le"
        return data.decode(encoding, errors="ignore")
    return data.decode("utf-8-sig", errors="ignore")


def deobfuscate_string_array(data: bytes) -> tuple[dict, bytes | None]:
    """Statically decode a rotated, custom-Base64 JavaScript string array."""
    text = decode_script_text(data)
    array_match = re.search(r"function\s+(a0_0x[0-9a-f]+)\(\)\{var\s+\w+=\[", text)
    if not array_match or _CUSTOM_BASE64 not in text:
        return {"status": "pattern_not_found", "executed": False}, None
    try:
        start = text.index("[", array_match.start())
        end = _matching_bracket(text, start)
        values = ast.literal_eval(text[start : end + 1])
    except (ValueError, SyntaxError):
        return {"status": "array_parse_failed", "executed": False}, None
    if not isinstance(values, list) or not 1 <= len(values) <= 10000:
        return {"status": "array_size_blocked", "executed": False}, None
    if not all(isinstance(value, str) and len(value) <= 65536 for value in values):
        return {"status": "array_value_blocked", "executed": False}, None

    alphabet_offset = text.index(_CUSTOM_BASE64)
    decoder_start = text.rfind("function a0_", 0, alphabet_offset)
    decoder_header = re.match(
        r"function\s+(a0_0x[0-9a-f]+)\(([^)]*)\)\{", text[decoder_start:]
    )
    if decoder_start < 0 or not decoder_header:
        return {"status": "decoder_parse_failed", "executed": False}, None
    decoder_name = decoder_header.group(1)
    first_argument = decoder_header.group(2).split(",")[0]
    decoder_prefix = text[decoder_start:alphabet_offset]
    offset_match = re.search(
        re.escape(first_argument) + r"=" + re.escape(first_argument) + r"-(\([^;]+\));",
        decoder_prefix,
    )
    if not offset_match:
        return {"status": "decoder_offset_missing", "executed": False}, None
    try:
        decoder_offset = int(_safe_arithmetic(offset_match.group(1)))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "decoder_offset_invalid", "executed": False}, None

    preamble = text[: min(len(text), 8192)]
    rotation_match = re.search(
        r"try\{var\s+\w+=(.*?);if\(\w+===\w+\)break", preamble, re.S
    )
    target_match = re.search(
        r"\}\(" + re.escape(array_match.group(1)) + r",([^;]+)\)\);", preamble
    )
    if not rotation_match or not target_match:
        return {"status": "rotation_parse_failed", "executed": False}, None
    expression = re.sub(
        r"parseInt\(\w+\((0x[0-9a-f]+)\)\)", r"p(\1)", rotation_match.group(1)
    )
    try:
        target = _safe_arithmetic(target_match.group(1))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "rotation_target_invalid", "executed": False}, None

    rotated = list(values)
    rotation = None
    for count in range(len(rotated)):

        def parse_at(index: int) -> float:
            position = index - decoder_offset
            if not 0 <= position < len(rotated):
                return math.nan
            return _javascript_parse_int(_decode_literal(rotated[position]))

        try:
            observed = _safe_arithmetic(expression, parse_at)
        except (SyntaxError, ValueError, ZeroDivisionError):
            observed = math.nan
        if observed == target:
            rotation = count
            break
        rotated.append(rotated.pop(0))
    if rotation is None:
        return {
            "status": "rotation_not_solved",
            "array_size": len(values),
            "decoder_offset": decoder_offset,
            "executed": False,
        }, None

    aliases = {decoder_name}
    aliases.update(
        re.findall(r"\b(a0_0x[0-9a-f]+)\s*=\s*" + re.escape(decoder_name), text)
    )
    call_pattern = re.compile(
        r"\b(" + "|".join(map(re.escape, sorted(aliases))) + r")\((0x[0-9a-f]+)\)"
    )
    decoded_count = 0

    def substitute(match: re.Match[str]) -> str:
        nonlocal decoded_count
        index = int(match.group(2), 16) - decoder_offset
        if not 0 <= index < len(rotated):
            return match.group()
        decoded = _decode_literal(rotated[index])
        if not decoded:
            return match.group()
        decoded_count += 1
        return json.dumps(decoded, ensure_ascii=False)

    transformed = _fold_literal_additions(call_pattern.sub(substitute, text))
    urls = sorted(set(re.findall(r"https?://[^\s\"'`<>]{4,512}", transformed, re.I)))
    output = transformed.encode("utf-8")
    return {
        "status": "deobfuscated",
        "array_size": len(values),
        "rotation": rotation,
        "decoder_offset": decoder_offset,
        "aliases": sorted(aliases),
        "substitutions": decoded_count,
        "urls": urls[:128],
        "executed": False,
    }, output


def deobfuscate_plain_string_array(data: bytes) -> tuple[dict, bytes | None]:
    """Statically resolve a rotated plain-string array decoder pattern.

    The supported shape uses a local array-returning function, an index-offset
    decoder, and a numeric ``parseInt`` rotation sentinel. No JavaScript is
    interpreted or executed.
    """
    text = decode_script_text(data)
    if len(text) > 2 * 1024 * 1024:
        return {"status": "script_size_blocked", "executed": False}, None
    array_match = re.search(
        r"function\s+([A-Za-z_$][\w$]*)\(\)\{(?:const|let|var)\s+[A-Za-z_$][\w$]*=\[",
        text,
    )
    if not array_match:
        return {"status": "pattern_not_found", "executed": False}, None
    array_function = array_match.group(1)
    try:
        start = text.index("[", array_match.start())
        end = _matching_bracket(text, start)
        values = ast.literal_eval(text[start : end + 1])
    except (ValueError, SyntaxError):
        return {"status": "array_parse_failed", "executed": False}, None
    if not isinstance(values, list) or not 1 <= len(values) <= 10000:
        return {"status": "array_size_blocked", "executed": False}, None
    if not all(isinstance(value, str) and len(value) <= 65536 for value in values):
        return {"status": "array_value_blocked", "executed": False}, None

    decoder_match = re.search(
        r"function\s+([A-Za-z_$][\w$]*)\(\s*([A-Za-z_$][\w$]*)[^)]*\)\{"
        r"\2\s*=\s*\2\s*-\s*(0x[0-9a-f]+|\d+)\s*;"
        r".{0,512}?\[\s*\2\s*\]",
        text,
        re.I | re.S,
    )
    if not decoder_match:
        return {"status": "decoder_parse_failed", "executed": False}, None
    decoder_name = decoder_match.group(1)
    decoder_offset = int(decoder_match.group(3), 0)

    rotation_match = re.search(
        r"\(function\([^)]*\)\{.{0,8192}?try\{(?:const|let|var)\s+\w+=(.*?);"
        r"if\(\w+===\w+\)break.{0,4096}?\}\}\("
        + re.escape(array_function)
        + r",([^;)]+)\)\);",
        text,
        re.S,
    )
    if not rotation_match:
        return {"status": "rotation_parse_failed", "executed": False}, None
    aliases = {decoder_name}
    rotation_block = rotation_match.group(0)
    aliases.update(
        re.findall(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            + re.escape(decoder_name)
            + r"\b",
            rotation_block,
        )
    )
    alias_pattern = "|".join(map(re.escape, sorted(aliases)))
    expression = re.sub(
        r"parseInt\((?:" + alias_pattern + r")\((0x[0-9a-f]+|\d+)\)\)",
        r"p(\1)",
        rotation_match.group(1),
    )
    try:
        target = _safe_arithmetic(rotation_match.group(2))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "rotation_target_invalid", "executed": False}, None

    rotated = list(values)
    rotation = None
    for count in range(len(rotated)):
        def parse_at(index: int) -> float:
            """Return JavaScript-like parseInt for one candidate array index."""
            position = index - decoder_offset
            if not 0 <= position < len(rotated):
                return math.nan
            return _javascript_parse_int(rotated[position])

        try:
            observed = _safe_arithmetic(expression, parse_at)
        except (SyntaxError, ValueError, ZeroDivisionError):
            observed = math.nan
        if observed == target:
            rotation = count
            break
        rotated.append(rotated.pop(0))
    if rotation is None:
        return {"status": "rotation_not_solved", "array_size": len(values), "executed": False}, None

    call_pattern = re.compile(
        r"\b(?:" + alias_pattern + r")\((0x[0-9a-f]+|\d+)\)"
    )
    substitutions = 0

    def substitute(match: re.Match[str]) -> str:
        """Replace one bounded decoder call with its selected string literal."""
        nonlocal substitutions
        index = int(match.group(1), 0) - decoder_offset
        if not 0 <= index < len(rotated):
            return match.group()
        substitutions += 1
        return json.dumps(rotated[index], ensure_ascii=False)

    transformed = _fold_literal_additions(call_pattern.sub(substitute, text))
    urls = sorted(set(re.findall(r"https?://[^\s\"'`<>]{4,512}", transformed, re.I)))
    return {
        "status": "deobfuscated",
        "array_size": len(values),
        "rotation": rotation,
        "decoder_offset": decoder_offset,
        "aliases": sorted(aliases),
        "substitutions": substitutions,
        "urls": urls[:128],
        "executed": False,
    }, transformed.encode("utf-8")
