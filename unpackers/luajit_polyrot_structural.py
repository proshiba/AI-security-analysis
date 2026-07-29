"""LuaJIT PolyRotローダーの文字表をリテラル表記に依存せず復元する。"""

from __future__ import annotations

import re

from unpackers import luajit_polyrot_auto as core


LUA_STRING = re.compile(r'"((?:\\[0-9]{1,3}|\\.|[^"\\])*)"')


def _decode_lua_string(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            output.append(value[index])
            index += 1
            continue
        index += 1
        decimal = re.match(r"[0-9]{1,3}", value[index:])
        if decimal:
            output.append(chr(int(decimal.group(0))))
            index += len(decimal.group(0))
            continue
        if index >= len(value):
            raise ValueError("Lua文字列エスケープが不完全です")
        simple = {"n": "\n", "r": "\r", "t": "\t"}
        output.append(simple.get(value[index], value[index]))
        index += 1
    return "".join(output)


def _row_values(body: str) -> list[list[str]]:
    rows: list[list[str]] = []
    depth = 0
    start: int | None = None
    quote: str | None = None
    escaped = False
    for index, value in enumerate(body):
        if quote is not None:
            if escaped:
                escaped = False
            elif value == "\\":
                escaped = True
            elif value == quote:
                quote = None
            continue
        if value in {"'", '"'}:
            quote = value
            continue
        if value == "{":
            depth += 1
            if depth == 2:
                start = index + 1
        elif value == "}":
            if depth == 2 and start is not None:
                decoded = [
                    _decode_lua_string(item)
                    for item in LUA_STRING.findall(body[start:index])
                ]
                rows.append([item for item in decoded if len(item) == 1])
                start = None
            depth -= 1
    return rows


def _substitution_table(text: str) -> tuple[str, list[list[str]]]:
    for match in re.finditer(r"\blocal\s+([A-Za-z_]\w*)\s*=\s*\{\{", text):
        opening = text.find("{", match.start())
        try:
            closing = core._matching_brace(text, opening)
        except ValueError:
            continue
        rows = _row_values(text[opening : closing + 1])
        if len(rows) == 25 and all(
            len(row) == 10 and len(set(row)) == 10 for row in rows
        ):
            return match.group(1), rows
    raise ValueError("25行の置換表が見つかりません")


def recover_all(text: str) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """数値エスケープと通常1文字が混在する置換表を使って復元する。"""
    if len(text.encode("utf-8", errors="ignore")) > core.MAX_SCRIPT_SIZE:
        return {"status": "size_blocked", "executed": False}, []
    anchors = (
        "PolyRot" in text,
        "E:sub(1,1)" in text,
        '"\\124"' in text,
        "NtAllocateVirtualMemory" in text,
    )
    if sum(anchors) < 3:
        return {"status": "pattern_not_found", "executed": False}, []
    try:
        table_name, rows = _substitution_table(text)
        target = core._target_alphabet(text)
    except ValueError as exc:
        return {
            "status": "structure_incomplete",
            "error": str(exc),
            "executed": False,
        }, []
    reports: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for match in core.HEADER.finditer(text):
        if len(match.group(2)) > core.MAX_LITERAL_SIZE:
            continue
        try:
            payload, report = core._decode_literal(
                match.group(1), match.group(2), table_name, rows, target
            )
        except ValueError:
            continue
        reports.append(report)
        digest = str(report["sha256"])
        if digest not in seen:
            artifacts.append(("luajit-polyrot-donut-shellcode", payload))
            seen.add(digest)
    return (
        {
            "status": "donut_shellcode_recovered" if artifacts else "pattern_not_found",
            "table_variable": table_name,
            "table_rows": len(rows),
            "payloads": reports,
            "executed": False,
            "network_contacted": False,
        },
        artifacts,
    )


def recover_bytes(data: bytes) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {"status": "not_utf8", "executed": False}, []
    return recover_all(text)
