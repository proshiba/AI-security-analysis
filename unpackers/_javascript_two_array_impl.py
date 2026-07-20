#!/usr/bin/env python3
"""二段の文字列配列を持つ reviewed JavaScript を非実行でデオブファスケートする。"""

from __future__ import annotations

import ast
import hashlib
import json
import re

try:
    from unpackers import _javascript_two_array_core as _core
except ModuleNotFoundError:  # ファイルを直接起動した場合
    import _javascript_two_array_core as _core  # type: ignore[no-redef]


REVIEWED_SHA256 = _core.REVIEWED_SHA256


def _extract_array(text: str, function: str, *, evaluate: bool) -> tuple[list[str], int, str]:
    function_start = text.index(f"function {function}")
    start = text.index("[", function_start)
    end = _core._matching_bracket(text, start)
    literal = text[start : end + 1]
    if not evaluate:
        return [], end, literal
    values = ast.literal_eval(literal)
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"{function} は文字列配列ではありません")
    return values, end, literal


def deobfuscate(data: bytes) -> tuple[dict[str, object], bytes]:
    """reviewed検体だけを、配列置換と定数演算によって復元する。"""
    digest = hashlib.sha256(data).hexdigest()
    if digest != REVIEWED_SHA256:
        raise ValueError("reviewed f146 SHA-256 と一致しません")
    text = data.decode("utf-8")
    definitions = _core._wrappers(text)

    first, _, _ = _extract_array(text, "_0x4ca4", evaluate=True)
    first_rotation = re.search(
        r"try\{var\s+\w+=(.*?);if\(\w+===\w+\)break.*?\}\}\(_0x4ca4,(0x[0-9a-f]+)\)\);",
        text[:250000],
        re.S | re.I,
    )
    if not first_rotation:
        raise ValueError("第一配列の rotation 式がありません")
    first, first_count = _core._solve_rotation(
        first,
        first_rotation.group(1),
        _core._numeric(first_rotation.group(2)),
        0x183,
        definitions,
        ("_0x5052",),
    )

    _, _, second_literal = _extract_array(text, "_0x38a0", evaluate=False)
    reduced_literal, nested_count = _core._replace_wrappers(
        second_literal, first, definitions, 0x183
    )
    remaining = sorted(
        set(re.findall(r"_0x[0-9a-f]+\([^)]*\)", reduced_literal, re.I))
    )
    if remaining:
        raise ValueError(f"第二配列に未解決の呼出しが {len(remaining)} 個あります")
    second = ast.literal_eval(reduced_literal)
    if not isinstance(second, list) or not all(isinstance(value, str) for value in second):
        raise ValueError("第二配列は文字列配列ではありません")

    # この検体では第二rotation IIFEが配列関数定義より前にある。
    second_rotation = re.search(
        r"try\{var\s+\w+=(.*?);if\(\w+===\w+\)break.*?\}\}\(_0x38a0,(0x[0-9a-f]+)\)\);",
        text,
        re.S | re.I,
    )
    if not second_rotation:
        raise ValueError("第二配列の rotation 式がありません")
    second, second_count = _core._solve_rotation(
        second,
        second_rotation.group(1),
        _core._numeric(second_rotation.group(2)),
        0x14C,
        definitions,
        ("_0x34d9", "_0x2e94c4"),
    )

    transformed, first_total = _core._replace_wrappers(text, first, definitions, 0x183)
    second_calls = re.compile(r"\b(?:_0x34d9|_0x5c5990)\((0x[0-9a-f]+|\d+)\)")
    second_total = 0

    def replace_second(match: re.Match[str]) -> str:
        nonlocal second_total
        position = int(match.group(1), 0) - 0x14C
        if not 0 <= position < len(second):
            return match.group()
        second_total += 1
        return json.dumps(second[position], ensure_ascii=False)

    transformed = _core._fold_literal_additions(
        second_calls.sub(replace_second, transformed)
    )
    output = transformed.encode()
    report: dict[str, object] = {
        "schema_version": 1,
        "executed": False,
        "first_array_size": len(first),
        "first_rotation": first_count,
        "second_array_size": len(second),
        "second_rotation": second_count,
        "wrapper_count": len(definitions),
        "nested_substitutions": nested_count,
        "first_substitutions": first_total,
        "second_substitutions": second_total,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output_size": len(output),
    }
    return report, output


_core.deobfuscate = deobfuscate
main = _core.main


if __name__ == "__main__":
    raise SystemExit(main())
