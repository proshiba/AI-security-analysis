#!/usr/bin/env python3
"""二段の文字列配列を持つ reviewed JavaScript を非実行でデオブファスケートする。"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path

try:
    from unpackers.javascript_obfuscator import (
        _fold_literal_additions,
        _javascript_parse_int,
        _matching_bracket,
        _safe_arithmetic,
    )
except ModuleNotFoundError:  # ファイルを直接起動した場合
    from javascript_obfuscator import (  # type: ignore[no-redef]
        _fold_literal_additions,
        _javascript_parse_int,
        _matching_bracket,
        _safe_arithmetic,
    )


REVIEWED_SHA256 = "f14655228657a022190bb4c10effad9e92f2c5b77e14f56ee2b747129dfd047d"


def _array(text: str, function: str) -> tuple[list[str], int, str]:
    function_start = text.index(f"function {function}")
    start = text.index("[", function_start)
    end = _matching_bracket(text, start)
    literal = text[start : end + 1]
    values = ast.literal_eval(literal)
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError(f"{function} は文字列配列ではありません")
    return values, end, literal


def _numeric(expression: str, names: dict[str, float] | None = None) -> float:
    names = names or {}
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
        if isinstance(node, ast.Name) and node.id in names:
            return float(names[node.id])
        if isinstance(node, ast.BinOp) and type(node.op) in binary:
            return binary[type(node.op)](visit(node.left), visit(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in unary:
            return unary[type(node.op)](visit(node.operand))
        raise ValueError(f"未対応の数式です: {ast.dump(node)}")

    return visit(ast.parse(expression, mode="eval"))


def _wrappers(text: str) -> dict[str, tuple[list[str], str]]:
    result: dict[str, tuple[list[str], str]] = {}
    pattern = re.compile(
        r"function\s+(_0x[0-9a-f]+)\(([^)]*)\)\{return\s+_0x5052\(([^,;]+),[^;]+\);\}",
        re.I,
    )
    for match in pattern.finditer(text):
        result[match.group(1)] = (
            [item.strip() for item in match.group(2).split(",")],
            match.group(3),
        )
    return result


def _wrapper_index(
    name: str,
    arguments: str,
    definitions: dict[str, tuple[list[str], str]],
) -> int:
    parameters, expression = definitions[name]
    raw_arguments = [item.strip() for item in arguments.split(",")]
    if len(parameters) != len(raw_arguments):
        raise ValueError("引数の数が一致しません")
    scope = {
        parameter: _numeric(argument)
        for parameter, argument in zip(parameters, raw_arguments, strict=True)
    }
    return int(_numeric(expression, scope))


def _solve_rotation(
    values: list[str],
    expression: str,
    target: float,
    offset: int,
    definitions: dict[str, tuple[list[str], str]],
    direct_aliases: tuple[str, ...],
) -> tuple[list[str], int]:
    call_names = "|".join(re.escape(name) for name in sorted(definitions))
    wrapper_call = re.compile(
        r"parseInt\((" + call_names + r")\(([-+xXa-fA-F0-9, ]+)\)\)"
    )
    expression = wrapper_call.sub(
        lambda match: f"p({_wrapper_index(match.group(1), match.group(2), definitions)})",
        expression,
    )
    for alias in direct_aliases:
        expression = re.sub(
            r"parseInt\(" + re.escape(alias) + r"\((0x[0-9a-f]+|\d+)\)\)",
            r"p(\1)",
            expression,
        )
    rotated = list(values)
    for count in range(len(rotated)):
        def parse_at(index: int) -> float:
            position = index - offset
            if not 0 <= position < len(rotated):
                return float("nan")
            return _javascript_parse_int(rotated[position])

        try:
            observed = _safe_arithmetic(expression, parse_at)
        except (SyntaxError, ValueError, ZeroDivisionError):
            observed = float("nan")
        if observed == target:
            return rotated, count
        rotated.append(rotated.pop(0))
    raise ValueError("配列 rotation を解決できません")


def _replace_wrappers(
    text: str,
    values: list[str],
    definitions: dict[str, tuple[list[str], str]],
    offset: int,
) -> tuple[str, int]:
    names = "|".join(re.escape(name) for name in sorted(definitions))
    pattern = re.compile(r"\b(" + names + r")\(([-+xXa-fA-F0-9, ]+)\)")
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        try:
            position = _wrapper_index(match.group(1), match.group(2), definitions) - offset
        except (SyntaxError, ValueError, ZeroDivisionError):
            return match.group()
        if not 0 <= position < len(values):
            return match.group()
        count += 1
        return json.dumps(values[position], ensure_ascii=False)

    return pattern.sub(replace, text), count


def deobfuscate(data: bytes) -> tuple[dict[str, object], bytes]:
    digest = hashlib.sha256(data).hexdigest()
    if digest != REVIEWED_SHA256:
        raise ValueError("reviewed f146 SHA-256 と一致しません")
    text = data.decode("utf-8")
    definitions = _wrappers(text)

    first, _, _ = _array(text, "_0x4ca4")
    rotation1 = re.search(
        r"try\{var\s+\w+=(.*?);if\(\w+===\w+\)break.*?\}\}\(_0x4ca4,(0x[0-9a-f]+)\)\);",
        text[:250000],
        re.S | re.I,
    )
    if not rotation1:
        raise ValueError("第一配列の rotation 式がありません")
    first, first_count = _solve_rotation(
        first,
        rotation1.group(1),
        _numeric(rotation1.group(2)),
        0x183,
        definitions,
        ("_0x5052",),
    )

    _, second_end, second_literal = _array(text, "_0x38a0")
    reduced, nested_count = _replace_wrappers(second_literal, first, definitions, 0x183)
    remaining = sorted(set(re.findall(r"_0x[0-9a-f]+\([^)]*\)", reduced, re.I)))
    if remaining:
        raise ValueError(f"第二配列に未解決の呼出しが {len(remaining)} 個あります")
    second = ast.literal_eval(reduced)
    if not isinstance(second, list) or not all(isinstance(value, str) for value in second):
        raise ValueError("第二配列は文字列配列ではありません")

    rotation2 = re.search(
        r"try\{var\s+\w+=(.*?);if\(\w+===\w+\)break.*?\}\}\(_0x38a0,(0x[0-9a-f]+)\)\);",
        text[second_end : second_end + 20000],
        re.S | re.I,
    )
    if not rotation2:
        raise ValueError("第二配列の rotation 式がありません")
    second, second_count = _solve_rotation(
        second,
        rotation2.group(1),
        _numeric(rotation2.group(2)),
        0x14C,
        definitions,
        ("_0x34d9", "_0x2e94c4"),
    )

    transformed, first_total = _replace_wrappers(text, first, definitions, 0x183)
    second_calls = re.compile(r"\b(?:_0x34d9|_0x5c5990)\((0x[0-9a-f]+|\d+)\)")
    second_total = 0

    def replace_second(match: re.Match[str]) -> str:
        nonlocal second_total
        position = int(match.group(1), 0) - 0x14C
        if not 0 <= position < len(second):
            return match.group()
        second_total += 1
        return json.dumps(second[position], ensure_ascii=False)

    transformed = _fold_literal_additions(second_calls.sub(replace_second, transformed))
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    report, output = deobfuscate(args.input.read_bytes())
    if args.output:
        args.output.write_bytes(output)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
