#!/usr/bin/env python3
"""LuaJITスクリプト内の置換・反転・Base64・PolyRot層を構造から復元する。"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
from pathlib import Path

from unpackers.donut_unpacker import is_donut_shellcode


MAX_SCRIPT_SIZE = 128 * 1024 * 1024
MAX_LITERAL_SIZE = 64 * 1024 * 1024
HEADER = re.compile(
    r'\blocal\s+([A-Za-z_]\w*)\s*=\s*"(\|[0-9A-O][^"]{1024,})"'
)
DECIMAL_ESCAPE = re.compile(r'"\\([0-9]{1,3})"')


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inverse_polyrot(data: bytes) -> bytes:
    """先頭マーカーから94文字範囲の回転量を戻す。"""
    if not data or not 128 <= data[0] <= 221:
        raise ValueError("PolyRotヘッダーが不正です")
    rotation = 94 - (data[0] - 128)
    return bytes(
        33 + ((value - 33 + rotation) % 94) if 33 <= value <= 126 else value
        for value in data[1:]
    )


def _matching_brace(text: str, opening: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(text)):
        value = text[index]
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
        elif value == "{":
            depth += 1
        elif value == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("Luaテーブルが閉じていません")


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
                rows.append(
                    [
                        chr(int(item))
                        for item in DECIMAL_ESCAPE.findall(body[start:index])
                        if 0 <= int(item) <= 255
                    ]
                )
                start = None
            depth -= 1
    return rows


def _substitution_table(text: str) -> tuple[str, list[list[str]]]:
    """25行×10文字の置換表を構造から探す。"""
    for match in re.finditer(r"\blocal\s+([A-Za-z_]\w*)\s*=\s*\{\{", text):
        opening = text.find("{", match.start())
        try:
            closing = _matching_brace(text, opening)
        except ValueError:
            continue
        rows = _row_values(text[opening : closing + 1])
        if len(rows) == 25 and all(
            len(row) == 10 and len(set(row)) == 10 for row in rows
        ):
            return match.group(1), rows
    raise ValueError("25行の置換表が見つかりません")


def _target_alphabet(text: str) -> str:
    """置換先の10文字表をコードから検証する。"""
    for match in re.finditer(r"\blocal\s+[A-Za-z_]\w*\s*=\s*\{", text):
        opening = text.find("{", match.start())
        try:
            closing = _matching_brace(text, opening)
        except ValueError:
            continue
        if closing - opening > 256:
            continue
        values = [
            chr(int(item))
            for item in DECIMAL_ESCAPE.findall(text[opening : closing + 1])
            if 0 <= int(item) <= 255
        ]
        if len(values) == 10 and "".join(values) == "ABCDEFabcd":
            return "".join(values)
    raise ValueError("置換先アルファベットが見つかりません")


def _selector(value: str) -> int:
    token = value[1]
    if "0" <= token <= "9":
        return ord(token) - ord("0")
    if "A" <= token <= "O":
        return 10 + ord(token) - ord("A")
    raise ValueError("置換表セレクターが不正です")


def _decode_literal(
    variable: str,
    value: str,
    table_name: str,
    rows: list[list[str]],
    target: str,
) -> tuple[bytes, dict[str, object]]:
    row_index = _selector(value)
    source = "".join(rows[row_index])
    translated = value[2:].translate(str.maketrans(source, target))[::-1]
    try:
        rotated = base64.b64decode(translated, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("置換後の値が正しいBase64ではありません") from exc
    payload = inverse_polyrot(rotated)
    if not is_donut_shellcode(payload):
        raise ValueError("復元結果が厳密なDonutシェルコード構造ではありません")
    return payload, {
        "variable": variable,
        "header": value[:2],
        "table_variable": table_name,
        "table_row": row_index,
        "source_alphabet": source,
        "target_alphabet": target,
        "encoded_size": len(value) - 2,
        "polyrot_size": len(rotated),
        "sha256": _sha256(payload),
        "size": len(payload),
        "magic_hex": payload[:16].hex(),
        "artifact_kind": "donut_shellcode",
        "executed": False,
        "network_contacted": False,
    }


def recover_all(text: str) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """検体ハッシュを使わず、構造が一致する全埋め込みDonut層を復元する。"""
    if len(text.encode("utf-8", errors="ignore")) > MAX_SCRIPT_SIZE:
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
        target = _target_alphabet(text)
    except ValueError as exc:
        return {
            "status": "structure_incomplete",
            "error": str(exc),
            "executed": False,
        }, []
    reports: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for match in HEADER.finditer(text):
        if len(match.group(2)) > MAX_LITERAL_SIZE:
            continue
        try:
            payload, report = _decode_literal(
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--artifact-xor-a5", type=Path)
    args = parser.parse_args()
    report, artifacts = recover_bytes(args.input.read_bytes())
    if not artifacts:
        raise ValueError(f"LuaJIT PolyRot層を復元できません: {report['status']}")
    if args.artifact_xor_a5:
        args.artifact_xor_a5.write_bytes(
            bytes(value ^ 0xA5 for value in artifacts[0][1])
        )
        report["artifact_storage"] = "xor-a5"
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
