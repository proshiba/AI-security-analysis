"""Static JavaScript string-array deobfuscation without executing JavaScript."""

from __future__ import annotations

import ast
import base64
import json
import math
import re
import time
from collections.abc import Callable

_CUSTOM_BASE64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
_STANDARD_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_TRANSLATION = str.maketrans(_CUSTOM_BASE64, _STANDARD_BASE64)
_RC4_ALIAS_ASSIGNMENT_LIMIT = 4096
_RC4_ALIAS_COUNT_LIMIT = 256
_RC4_ALIAS_DEPTH_LIMIT = 16
_RC4_ALIAS_ELAPSED_SECONDS = 2.0
_PLAIN_STRING_ARRAY_SCRIPT_SIZE_LIMIT = 8 * 1024 * 1024


def _bounded_alias_closure(
    text: str,
    decoder_name: str,
) -> tuple[set[str], int, str | None]:
    """単純代入だけを辿り、decoder aliasの有界な推移閉包を返す。"""
    started = time.monotonic()

    def timed_out() -> bool:
        return time.monotonic() - started > _RC4_ALIAS_ELAPSED_SECONDS

    # lookaheadで``a=b=c``の``a=b``と``b=c``を重ねて取得する。右辺の
    # 直後を区切り記号へ限定し、``a=b()``や``a=b+1``をaliasにしない。
    assignment = re.compile(
        r"(?<![=!<>\w$])(?=([A-Za-z_$][\w$]*)\s*=\s*(?![=>])"
        r"([A-Za-z_$][\w$]*)\s*(?==|[,;)}\]]|$))"
    )
    sources: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for assignment_count, match in enumerate(assignment.finditer(text), start=1):
        if timed_out():
            return {decoder_name}, 0, "decoder_alias_time_exceeded"
        if assignment_count > _RC4_ALIAS_ASSIGNMENT_LIMIT:
            return {decoder_name}, 0, "decoder_alias_assignment_limit_exceeded"
        left, right = match.group(1), match.group(2)
        sources.setdefault(left, set()).add(right)
        reverse.setdefault(right, set()).add(left)

    # decoderと代入グラフ上で連結した成分だけを監査する。無関係な変数の
    # cycleや再代入を、このdecoderの曖昧性として誤検出しない。
    component = {decoder_name}
    pending = [decoder_name]
    while pending:
        if timed_out():
            return {decoder_name}, 0, "decoder_alias_time_exceeded"
        current = pending.pop()
        neighbours = sources.get(current, set()) | reverse.get(current, set())
        for neighbour in neighbours:
            if neighbour in component:
                continue
            component.add(neighbour)
            if len(component) - 1 > _RC4_ALIAS_COUNT_LIMIT:
                return {decoder_name}, 0, "decoder_alias_count_exceeded"
            pending.append(neighbour)

    # 多重代入より先にcycleを明示検出し、循環参照を通常の曖昧性へ埋没させない。
    visiting: set[str] = set()
    visited: set[str] = set()

    def has_cycle(node: str) -> bool:
        if timed_out():
            raise TimeoutError
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for source in sources.get(node, set()):
            if source in component and has_cycle(source):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    try:
        if any(has_cycle(node) for node in component if node not in visited):
            return {decoder_name}, 0, "decoder_alias_cycle"
    except TimeoutError:
        return {decoder_name}, 0, "decoder_alias_time_exceeded"

    if decoder_name in sources or any(
        len(sources.get(node, set())) > 1 for node in component
    ):
        return {decoder_name}, 0, "decoder_alias_ambiguous"

    aliases = {decoder_name}
    depths = {decoder_name: 0}
    pending = [decoder_name]
    while pending:
        if timed_out():
            return {decoder_name}, 0, "decoder_alias_time_exceeded"
        source = pending.pop(0)
        for alias in reverse.get(source, set()):
            if alias in aliases:
                continue
            depth = depths[source] + 1
            if depth > _RC4_ALIAS_DEPTH_LIMIT:
                return {decoder_name}, 0, "decoder_alias_depth_exceeded"
            aliases.add(alias)
            depths[alias] = depth
            pending.append(alias)
    return aliases, max(depths.values()), None


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


def _matching_brace(text: str, start: int) -> int:
    """文字列とコメント内の波括弧を除外し、関数本体の終端を探す。"""
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = start
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if character in {"\r", "\n"}:
                line_comment = False
        elif block_comment:
            if character == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character == "/" and following == "/":
            line_comment = True
            index += 1
        elif character == "/" and following == "*":
            block_comment = True
            index += 1
        elif character in {"'", '"', "`"}:
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ValueError("unterminated JavaScript function body")


def _decode_literal(value: str) -> str:
    """Decode the alphabet-swapped Base64 routine used by the obfuscator."""
    translated = value.translate(_TRANSLATION)
    translated += "=" * (-len(translated) % 4)
    try:
        return base64.b64decode(translated, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""


def _rc4_text(value: str, key: str) -> str:
    """JavaScriptの``charCodeAt``版RC4を文字列として再現する。"""
    if not key or len(key) > 4096:
        raise ValueError("RC4 key length is outside the supported range")
    state = list(range(256))
    cursor = 0
    for index in range(256):
        cursor = (cursor + state[index] + ord(key[index % len(key)])) & 0xFF
        state[index], state[cursor] = state[cursor], state[index]
    left = 0
    right = 0
    output: list[str] = []
    for character in value:
        left = (left + 1) & 0xFF
        right = (right + state[left]) & 0xFF
        state[left], state[right] = state[right], state[left]
        output.append(chr(ord(character) ^ state[(state[left] + state[right]) & 0xFF]))
    return "".join(output)


def _decode_rc4_literal(value: str, key: str) -> str:
    decoded = _decode_literal(value)
    return _rc4_text(decoded, key) if decoded else ""


def _javascript_string_literal(value: str) -> str:
    """限定した引用文字列をPython文字列へ変換する。"""
    try:
        decoded = ast.literal_eval(value)
    except (SyntaxError, ValueError) as exc:
        raise ValueError("invalid JavaScript string literal") from exc
    if not isinstance(decoded, str) or len(decoded) > 4096:
        raise ValueError("JavaScript string literal is outside the supported range")
    return decoded


def _safe_rc4_rotation_arithmetic(
    expression: str,
    parse_value: Callable[[int, str], float],
) -> float:
    """数値演算と``p(index, key)``だけでrotation式を評価する。"""
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
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "p"
            and len(node.args) == 2
            and not node.keywords
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            return float(parse_value(int(visit(node.args[0])), node.args[1].value))
        raise ValueError("unsupported RC4 rotation syntax")

    return visit(ast.parse(expression, mode="eval"))


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
        r"try\{var\s+\w+=(.*?);if\(\w+===\w+\)break", preamble, re.DOTALL
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
    urls = sorted(
        set(
            re.findall(
                r"https?://[^\s\"'`<>]{4,512}",
                transformed,
                re.IGNORECASE,
            )
        )
    )
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


def deobfuscate_rc4_string_array(data: bytes) -> tuple[dict, bytes | None]:
    """custom Base64＋RC4型の文字列配列をJavaScript非実行で復号する。

    obfuscator.io系の識別子は毎回変わるため固定名へ依存しない。配列、decoder
    offset、RC4の256-byte KSA/PRGA形状、呼出しの即値indexと文字列鍵をすべて
    構造で照合する。rotation式も数値演算と``parseInt``だけに限定して解く。
    """
    text = decode_script_text(data)
    if len(text) > 8 * 1024 * 1024:
        return {"status": "script_size_blocked", "executed": False}, None
    if _CUSTOM_BASE64 not in text:
        return {"status": "pattern_not_found", "executed": False}, None

    array_matches = list(
        re.finditer(
            r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{\s*"
            r"(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*\[",
            text,
        )
    )
    if not array_matches or len(array_matches) > 512:
        return {"status": "pattern_not_found", "executed": False}, None
    arrays: dict[str, list[str]] = {}
    for array_match in array_matches:
        try:
            start = text.index("[", array_match.start())
            end = _matching_bracket(text, start)
            values = ast.literal_eval(text[start : end + 1])
        except (SyntaxError, ValueError):
            continue
        if not isinstance(values, list) or not 1 <= len(values) <= 10000:
            continue
        if not all(isinstance(value, str) and len(value) <= 65536 for value in values):
            continue
        arrays[array_match.group(1)] = values
    if not arrays:
        return {"status": "array_parse_failed", "executed": False}, None

    # obfuscator.io系には「配列→decoder」と「decoder→配列」の両配置がある。
    # 位置関係だけで選ばず、decoder内の配列参照、custom Base64 alphabet、
    # RC4 KSA/PRGA形状、index offsetを同時に要求して一意に決定する。
    decoder_candidates = list(
        re.finditer(
            r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*"
            r"([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*\{",
            text,
        )
    )
    if not decoder_candidates or len(decoder_candidates) > 512:
        return {"status": "decoder_parse_failed", "executed": False}, None

    selected_decoders: list[
        tuple[re.Match[str], str, re.Match[str], str, list[str]]
    ] = []
    for candidate in decoder_candidates:
        try:
            body_start = candidate.end() - 1
            body_end = _matching_brace(text, body_start)
        except ValueError:
            continue
        candidate_window = text[candidate.start() : body_end + 1]
        if len(candidate_window) > 65536:
            continue
        index_name = candidate.group(2)
        candidate_offset = re.search(
            re.escape(index_name)
            + r"\s*=\s*"
            + re.escape(index_name)
            + r"\s*-\s*(\([^;]{1,256}\)|0x[0-9a-fA-F]+|\d+)\s*;",
            candidate_window,
        )
        referenced_arrays = [
            array_function
            for array_function in arrays
            if re.search(
                r"\b" + re.escape(array_function) + r"\s*\(\s*\)",
                candidate_window,
            )
        ]
        if (
            candidate_offset is not None
            and len(referenced_arrays) == 1
            and _CUSTOM_BASE64 in candidate_window
            and all(
                marker in candidate_window
                for marker in ("0x100", "charCodeAt", "fromCharCode")
            )
        ):
            array_function = referenced_arrays[0]
            selected_decoders.append(
                (
                    candidate,
                    candidate_window,
                    candidate_offset,
                    array_function,
                    arrays[array_function],
                )
            )
    if not selected_decoders or len(selected_decoders) > 32:
        return {
            "status": (
                "decoder_parse_failed"
                if not selected_decoders
                else "decoder_count_blocked"
            ),
            "decoder_candidate_count": len(selected_decoders),
            "executed": False,
        }, None
    quoted = r"(?:'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
    transformed = text
    decoder_reports: list[dict] = []
    all_aliases: set[str] = set()
    substitutions = 0
    decode_failures = 0
    for (
        decoder_header,
        _decoder_window,
        offset_match,
        array_function,
        values,
    ) in selected_decoders:
        decoder_start = decoder_header.start()
        decoder_name = decoder_header.group(1)
        try:
            decoder_offset = int(_safe_arithmetic(offset_match.group(1)))
        except (SyntaxError, ValueError, ZeroDivisionError):
            return {"status": "decoder_offset_invalid", "executed": False}, None

        aliases, alias_max_depth, alias_error = _bounded_alias_closure(
            text,
            decoder_name,
        )
        if alias_error is not None:
            return {"status": alias_error, "executed": False}, None
        if all_aliases.intersection(aliases):
            return {"status": "decoder_alias_ambiguous", "executed": False}, None
        all_aliases.update(aliases)
        alias_pattern = "|".join(
            map(re.escape, sorted(aliases, key=len, reverse=True))
        )
        call_pattern = re.compile(
            r"\b(?:" + alias_pattern + r")\(\s*"
            r"(0x[0-9a-fA-F]+|\d+)\s*,\s*(" + quoted + r")\s*\)"
        )

        rotated = list(values)
        rotation = 0
        rotation_source = "not_present"
        prefix = text[:decoder_start]
        iife_match = re.search(
            r"try\s*\{\s*(?:const|let|var)\s+\w+\s*=\s*(.*?);\s*"
            r"if\s*\(\s*\w+\s*===\s*\w+\s*\)\s*break.*?"
            r"\}\s*\}\s*\(\s*"
            + re.escape(array_function)
            + r"\s*,\s*([^;)]+)\s*\)\s*\)\s*;",
            prefix,
            re.DOTALL,
        )
        if iife_match:
            expression = re.sub(
                r"parseInt\(\s*(?:" + alias_pattern + r")\(\s*"
                r"(0x[0-9a-fA-F]+|\d+)\s*,\s*(" + quoted + r")\s*\)\s*\)",
                r"p(\1,\2)",
                iife_match.group(1),
            )
            try:
                target = _safe_arithmetic(iife_match.group(2))
            except (SyntaxError, ValueError, ZeroDivisionError):
                return {
                    "status": "rotation_target_invalid",
                    "executed": False,
                }, None
            solved: int | None = None
            for count in range(len(rotated)):

                def parse_at(
                    index: int,
                    key: str,
                    *,
                    current_offset: int = decoder_offset,
                    current_values: list[str] = rotated,
                ) -> float:
                    position = index - current_offset
                    if not 0 <= position < len(current_values):
                        return math.nan
                    try:
                        return _javascript_parse_int(
                            _decode_rc4_literal(current_values[position], key)
                        )
                    except ValueError:
                        return math.nan

                try:
                    observed = _safe_rc4_rotation_arithmetic(expression, parse_at)
                except (SyntaxError, ValueError, ZeroDivisionError):
                    observed = math.nan
                if observed == target:
                    solved = count
                    break
                rotated.append(rotated.pop(0))
            if solved is None:
                return {
                    "status": "rotation_not_solved",
                    "array_size": len(values),
                    "executed": False,
                }, None
            rotation = solved
            rotation_source = "sentinel"

        pair_substitutions = 0
        pair_failures = 0

        def substitute(
            match: re.Match[str],
            *,
            current_offset: int = decoder_offset,
            current_values: list[str] = rotated,
        ) -> str:
            nonlocal pair_substitutions, pair_failures
            index = int(match.group(1), 0) - current_offset
            if not 0 <= index < len(current_values):
                pair_failures += 1
                return match.group()
            try:
                key = _javascript_string_literal(match.group(2))
                decoded = _decode_rc4_literal(current_values[index], key)
            except (UnicodeError, ValueError):
                pair_failures += 1
                return match.group()
            if not decoded:
                pair_failures += 1
                return match.group()
            pair_substitutions += 1
            return json.dumps(decoded, ensure_ascii=False)

        transformed = call_pattern.sub(substitute, transformed)
        substitutions += pair_substitutions
        decode_failures += pair_failures
        decoder_reports.append(
            {
                "array_function": array_function,
                "array_size": len(values),
                "decoder": decoder_name,
                "decoder_offset": decoder_offset,
                "aliases": sorted(aliases),
                "alias_count": len(aliases) - 1,
                "alias_max_depth": alias_max_depth,
                "rotation": rotation,
                "rotation_source": rotation_source,
                "substitutions": pair_substitutions,
                "decode_failures": pair_failures,
            }
        )

    transformed = _fold_literal_additions(transformed)
    if substitutions == 0:
        return {
            "status": "calls_not_resolved",
            "decoder_count": len(decoder_reports),
            "executed": False,
        }, None
    urls = sorted(
        set(
            re.findall(
                r"https?://[^\s\"'`<>]{4,512}",
                transformed,
                re.IGNORECASE,
            )
        )
    )
    primary = decoder_reports[0]
    report = {
        "status": "deobfuscated",
        "variant": "custom_base64_rc4_string_array",
        "array_size": primary["array_size"],
        "rotation": primary["rotation"],
        "rotation_source": primary["rotation_source"],
        "decoder_offset": primary["decoder_offset"],
        "aliases": primary["aliases"],
        "decoder_count": len(decoder_reports),
        "decoders": decoder_reports,
        "substitutions": substitutions,
        "decode_failures": decode_failures,
        "urls": urls[:128],
        "executed": False,
        "network_contacted": False,
    }
    return report, transformed.encode("utf-8")


def deobfuscate_plain_string_array(data: bytes) -> tuple[dict, bytes | None]:
    """平文文字列配列decoderをJavaScript非実行で静的に解決する。

    整形済みの複数配列／推移aliasを先に評価し、対象外の場合だけ既存の
    minified decoderへ進む。どちらもscriptを解釈または実行しない。
    """
    formatted_report, formatted_output = _deobfuscate_formatted_plain_string_arrays(
        data
    )
    if formatted_report["status"] != "pattern_not_found":
        return formatted_report, formatted_output
    text = decode_script_text(data)
    if len(text) > _PLAIN_STRING_ARRAY_SCRIPT_SIZE_LIMIT:
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

    decoder_matches = re.finditer(
        r"function\s+([A-Za-z_$][\w$]*)\(\s*([A-Za-z_$][\w$]*)[^)]*\)\{"
        r"\2\s*=\s*\2\s*-\s*(\([^;]{1,256}\)|0x[0-9a-f]+|\d+)\s*;"
        r".{0,1024}?\[\s*\2\s*\]",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    decoder_match = next(
        (
            match
            for match in decoder_matches
            if re.search(r"\b" + re.escape(array_function) + r"\s*\(\s*\)", match.group(0))
        ),
        None,
    )
    if decoder_match is None:
        return {"status": "decoder_parse_failed", "executed": False}, None
    decoder_name = decoder_match.group(1)
    try:
        decoder_offset = int(_safe_arithmetic(decoder_match.group(3)))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "decoder_offset_invalid", "executed": False}, None

    rotation_match = re.search(
        r"\(function\([^)]*\)\{.{0,8192}?try\{(?:const|let|var)\s+\w+=(.*?);"
        r"if\(\w+===\w+\)break.{0,4096}?\}\}\("
        + re.escape(array_function)
        + r",([^;)]+)\)\);",
        text,
        re.DOTALL,
    )
    aliases = {decoder_name}
    aliases.update(
        re.findall(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            + re.escape(decoder_name)
            + r"\b",
            text,
        )
    )
    alias_pattern = "|".join(map(re.escape, sorted(aliases)))

    rotated = list(values)
    rotation = 0
    rotation_source = "not_present"
    if rotation_match:
        expression = re.sub(
            r"parseInt\((?:" + alias_pattern + r")\((0x[0-9a-f]+|\d+)\)\)",
            r"p(\1)",
            rotation_match.group(1),
        )
        try:
            target = _safe_arithmetic(rotation_match.group(2))
        except (SyntaxError, ValueError, ZeroDivisionError):
            return {"status": "rotation_target_invalid", "executed": False}, None
        solved_rotation = None
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
                solved_rotation = count
                break
            rotated.append(rotated.pop(0))
        if solved_rotation is None:
            return {"status": "rotation_not_solved", "array_size": len(values), "executed": False}, None
        rotation = solved_rotation
        rotation_source = "sentinel"

    call_pattern = re.compile(
        r"\b(?:" + alias_pattern + r")\(\s*([^,()]{1,160})\s*\)"
    )
    substitutions = 0

    def substitute(match: re.Match[str]) -> str:
        """Replace one bounded decoder call with its selected string literal."""
        nonlocal substitutions
        try:
            index = int(_safe_arithmetic(match.group(1))) - decoder_offset
        except (SyntaxError, ValueError, ZeroDivisionError):
            return match.group()
        if not 0 <= index < len(rotated):
            return match.group()
        substitutions += 1
        return json.dumps(rotated[index], ensure_ascii=False)

    transformed = _fold_literal_additions(call_pattern.sub(substitute, text))
    urls = sorted(
        set(
            re.findall(
                r"https?://[^\s\"'`<>]{4,512}",
                transformed,
                re.IGNORECASE,
            )
        )
    )
    return {
        "status": "deobfuscated",
        "array_size": len(values),
        "rotation": rotation,
        "rotation_source": rotation_source,
        "decoder_offset": decoder_offset,
        "aliases": sorted(aliases),
        "substitutions": substitutions,
        "urls": urls[:128],
        "executed": False,
    }, transformed.encode("utf-8")


def _deobfuscate_formatted_plain_string_arrays(
    data: bytes,
) -> tuple[dict, bytes | None]:
    """複数配列を含む整形済みplain decoderを有界に静的復号する。"""

    text = decode_script_text(data)
    if len(text) > _PLAIN_STRING_ARRAY_SCRIPT_SIZE_LIMIT:
        return {"status": "script_size_blocked", "executed": False}, None
    array_headers = list(
        re.finditer(
            r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{",
            text,
        )
    )
    if not array_headers:
        return {"status": "pattern_not_found", "executed": False}, None
    if len(array_headers) > 512:
        return {"status": "array_count_blocked", "executed": False}, None
    arrays: dict[str, list[str]] = {}
    for array_header in array_headers:
        try:
            body_start = array_header.end() - 1
            body_end = _matching_brace(text, body_start)
            body = text[body_start + 1 : body_end]
            if len(body) > 65_536:
                continue
            assignments = list(
                re.finditer(
                    r"(?:\b(?:const|let|var)\s+|,)"
                    r"\s*[A-Za-z_$][\w$]*\s*=\s*\[",
                    body,
                )
            )
            if len(assignments) != 1:
                continue
            start = body_start + 1 + body.index("[", assignments[0].start())
            end = _matching_bracket(text, start)
            values = ast.literal_eval(text[start : end + 1])
        except (SyntaxError, ValueError):
            continue
        if not isinstance(values, list) or not 1 <= len(values) <= 10000:
            continue
        if not all(isinstance(value, str) and len(value) <= 65536 for value in values):
            continue
        arrays[array_header.group(1)] = values
    if not arrays:
        return {"status": "array_parse_failed", "executed": False}, None

    headers = list(
        re.finditer(
            r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*"
            r"([A-Za-z_$][\w$]*)[^)]*\)\s*\{",
            text,
        )
    )
    if len(headers) > 512:
        return {"status": "decoder_count_blocked", "executed": False}, None
    candidates: list[dict[str, object]] = []
    for header in headers:
        try:
            body_start = header.end() - 1
            body_end = _matching_brace(text, body_start)
        except ValueError:
            continue
        window = text[header.start() : body_end + 1]
        if len(window) > 65_536:
            continue
        index_name = header.group(2)
        offset = re.search(
            re.escape(index_name)
            + r"\s*=\s*"
            + re.escape(index_name)
            + r"\s*-\s*(\([^;]{1,256}\)|0x[0-9a-fA-F]+|\d+)\s*;",
            window,
        )
        referenced = [
            name
            for name in arrays
            if re.search(r"\b" + re.escape(name) + r"\s*\(\s*\)", window)
        ]
        if offset is None or len(referenced) != 1:
            continue
        if re.search(r"\[\s*" + re.escape(index_name) + r"\s*\]", window) is None:
            continue
        if _CUSTOM_BASE64 in window and all(
            marker in window for marker in ("0x100", "charCodeAt", "fromCharCode")
        ):
            continue
        decoder_name = header.group(1)
        aliases, alias_max_depth, alias_error = _bounded_alias_closure(
            text,
            decoder_name,
        )
        if alias_error is not None:
            return {"status": alias_error, "executed": False}, None
        alias_pattern = "|".join(
            map(re.escape, sorted(aliases, key=len, reverse=True))
        )
        calls = re.compile(
            r"\b(?:" + alias_pattern + r")\(\s*([^,()]{1,160})\s*\)"
        )
        if calls.search(text) is None:
            continue
        candidates.append(
            {
                "array_function": referenced[0],
                "values": arrays[referenced[0]],
                "decoder": decoder_name,
                "decoder_start": header.start(),
                "offset": offset.group(1),
                "aliases": aliases,
                "alias_max_depth": alias_max_depth,
                "alias_pattern": alias_pattern,
                "calls": calls,
            }
        )
    if not candidates:
        return {"status": "pattern_not_found", "executed": False}, None
    if len(candidates) > 32:
        return {"status": "decoder_count_blocked", "executed": False}, None

    transformed = text
    all_aliases: set[str] = set()
    reports: list[dict[str, object]] = []
    substitutions = 0
    for candidate in candidates:
        aliases = set(candidate["aliases"])
        if all_aliases.intersection(aliases):
            return {"status": "decoder_alias_ambiguous", "executed": False}, None
        all_aliases.update(aliases)
        try:
            decoder_offset = int(_safe_arithmetic(str(candidate["offset"])))
        except (SyntaxError, ValueError, ZeroDivisionError):
            return {"status": "decoder_offset_invalid", "executed": False}, None
        values = list(candidate["values"])
        rotated = list(values)
        rotation = 0
        rotation_source = "not_present"
        alias_pattern = str(candidate["alias_pattern"])
        prefix = text[: int(candidate["decoder_start"])]
        rotation_match = re.search(
            r"try\s*\{\s*(?:const|let|var)\s+\w+\s*=\s*(.*?);\s*"
            r"if\s*\(\s*\w+\s*===\s*\w+\s*\)\s*break.*?"
            r"\}\s*\}\s*\(\s*"
            + re.escape(str(candidate["array_function"]))
            + r"\s*,\s*([^;)]+)\s*\)\s*\)\s*;",
            prefix,
            re.DOTALL,
        )
        if rotation_match:
            expression = re.sub(
                r"parseInt\(\s*(?:" + alias_pattern + r")\(\s*"
                r"(0x[0-9a-fA-F]+|\d+)\s*\)\s*\)",
                r"p(\1)",
                rotation_match.group(1),
            )
            try:
                target = _safe_arithmetic(rotation_match.group(2))
            except (SyntaxError, ValueError, ZeroDivisionError):
                return {"status": "rotation_target_invalid", "executed": False}, None
            solved_rotation = None
            for count in range(len(rotated)):

                def parse_at(
                    index: int,
                    *,
                    current_offset: int = decoder_offset,
                    current_values: list[str] = rotated,
                ) -> float:
                    position = index - current_offset
                    if not 0 <= position < len(current_values):
                        return math.nan
                    return _javascript_parse_int(current_values[position])

                try:
                    observed = _safe_arithmetic(expression, parse_at)
                except (SyntaxError, ValueError, ZeroDivisionError):
                    observed = math.nan
                if observed == target:
                    solved_rotation = count
                    break
                rotated.append(rotated.pop(0))
            if solved_rotation is None:
                return {
                    "status": "rotation_not_solved",
                    "array_size": len(values),
                    "executed": False,
                }, None
            rotation = solved_rotation
            rotation_source = "sentinel"

        pair_substitutions = 0

        def substitute(
            match: re.Match[str],
            *,
            current_offset: int = decoder_offset,
            current_values: list[str] = rotated,
        ) -> str:
            nonlocal pair_substitutions
            try:
                index = int(_safe_arithmetic(match.group(1))) - current_offset
            except (SyntaxError, ValueError, ZeroDivisionError):
                return match.group()
            if not 0 <= index < len(current_values):
                return match.group()
            pair_substitutions += 1
            return json.dumps(current_values[index], ensure_ascii=False)

        calls = candidate["calls"]
        if not isinstance(calls, re.Pattern):
            return {"status": "decoder_parse_failed", "executed": False}, None
        transformed = calls.sub(substitute, transformed)
        substitutions += pair_substitutions
        reports.append(
            {
                "array_function": candidate["array_function"],
                "array_size": len(values),
                "decoder": candidate["decoder"],
                "decoder_offset": decoder_offset,
                "aliases": sorted(aliases),
                "alias_count": len(aliases) - 1,
                "alias_max_depth": candidate["alias_max_depth"],
                "rotation": rotation,
                "rotation_source": rotation_source,
                "substitutions": pair_substitutions,
            }
        )
    if substitutions == 0:
        return {
            "status": "calls_not_resolved",
            "decoder_count": len(reports),
            "executed": False,
        }, None
    transformed = _fold_literal_additions(transformed)
    urls = sorted(
        set(
            re.findall(
                r"https?://[^\s\"'`<>]{4,512}",
                transformed,
                re.IGNORECASE,
            )
        )
    )
    primary = reports[0]
    return {
        "status": "deobfuscated",
        "variant": "formatted_plain_string_array",
        "array_size": primary["array_size"],
        "rotation": primary["rotation"],
        "rotation_source": primary["rotation_source"],
        "decoder_offset": primary["decoder_offset"],
        "aliases": primary["aliases"],
        "decoder_count": len(reports),
        "decoders": reports,
        "substitutions": substitutions,
        "urls": urls[:128],
        "executed": False,
        "network_contacted": False,
    }, transformed.encode("utf-8")
