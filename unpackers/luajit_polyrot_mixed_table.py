#!/usr/bin/env python3
"""混在表記のLua置換表からBase64/PolyRot/Donut層を静的復元する。

従来の復元器が10進escapeだけを含む表を対象としていたのに対し、この亜種は
``"\\065"`` と ``"!"`` のようなescape・直接文字を同じ25行×10列の表へ
混在させる。本moduleはLuaを実行せず、次の構造が全て一致した場合だけ復元する。

* ``|0`` から ``|O`` までのselectorを持つ有界な長文字列
* 各行が相異なるASCII 1 byteだけで構成される25行×10列の置換表
* 固定置換先 ``ABCDEFabcd`` と標準Base64 alphabetの明示
* ``sub(1,1)`` と ``reverse()`` の静的な処理anchor
* 置換・反転・Base64・PolyRot解除後の厳格なDonut shellcode構造

入力、文字列、表、候補数に上限を設け、曖昧な構造や未対応escapeはfail-closedで
拒否する。検体実行およびnetwork通信は行わない。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from unpackers.donut_unpacker import is_donut_shellcode
from unpackers.luajit_polyrot_auto import inverse_polyrot

MAX_SCRIPT_SIZE = 128 * 1024 * 1024
MAX_LITERAL_SIZE = 64 * 1024 * 1024
MAX_TABLE_SIZE = 256 * 1024
MAX_TABLE_CANDIDATES = 64
MAX_PAYLOAD_LITERALS = 16
MAX_LOCAL_ASSIGNMENT_CANDIDATES = 8192
MAX_DECODED_LITERAL_BYTES = 96 * 1024 * 1024
MAX_TRANSFORM_ATTEMPTS = 128
MAX_TOTAL_TRANSFORM_BYTES = 256 * 1024 * 1024
MAX_TOTAL_QUOTED_SCAN_CHARS = 2 * MAX_SCRIPT_SIZE
MIN_PAYLOAD_SIZE = 1024
BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_ALLOWED = set(BASE64_ALPHABET + b"=")
TARGET_ALPHABET = b"ABCDEFabcd"
LOCAL_ASSIGNMENT = re.compile(r"\blocal\s+([A-Za-z_]\w*)\s*=\s*")
SOURCE_TABLE = re.compile(r"\blocal\s+([A-Za-z_]\w*)\s*=\s*\{\s*\{")


class RecoveryLimitError(ValueError):
    """候補集合または静的変換workが安全上限へ到達したことを示す。"""


class QuoteScanLimitError(RecoveryLimitError):
    """Lua quoted stringの累積走査量が安全上限へ到達したことを示す。"""


@dataclass
class _QuoteScanBudget:
    remaining: int

    def consume(self) -> None:
        if self.remaining <= 0:
            raise QuoteScanLimitError(
                "Lua quoted stringの累積走査量が上限を超えています"
            )
        self.remaining -= 1


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _quoted_end(
    text: str,
    opening: int,
    *,
    end: int,
    budget: _QuoteScanBudget,
) -> int:
    if not 0 <= opening < len(text) or text[opening] not in {'"', "'"}:
        raise ValueError("Lua文字列の開始位置が不正です")
    limit = min(len(text), max(opening + 1, end))
    quote = text[opening]
    escaped = False
    for index in range(opening + 1, limit):
        budget.consume()
        value = text[index]
        if escaped:
            escaped = False
        elif value == "\\":
            escaped = True
        elif value == quote:
            return index
    raise ValueError("Lua文字列が閉じていません")


def _matching_brace(
    text: str,
    opening: int,
    *,
    max_span: int,
    budget: _QuoteScanBudget,
) -> int:
    depth = 0
    index = opening
    limit = min(len(text), opening + max_span + 1)
    while index < limit:
        value = text[index]
        if value in {'"', "'"}:
            index = _quoted_end(text, index, end=limit, budget=budget) + 1
            continue
        if value == "{":
            depth += 1
        elif value == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    if limit < len(text):
        raise RecoveryLimitError("Luaテーブル走査が上限を超えています")
    raise ValueError("Luaテーブルが閉じていません")


def _decode_lua_string(value: str) -> bytes:
    """Lua 5.1互換の短いescapeだけを境界付きで復元する。"""

    output = bytearray()
    index = 0
    simple = {
        "a": 7,
        "b": 8,
        "f": 12,
        "n": 10,
        "r": 13,
        "t": 9,
        "v": 11,
        "\\": 92,
        '"': 34,
        "'": 39,
    }
    while index < len(value):
        if value[index] != "\\":
            encoded = value[index].encode("utf-8")
            if len(output) + len(encoded) > MAX_LITERAL_SIZE:
                raise ValueError("Lua文字列が上限を超えています")
            output.extend(encoded)
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise ValueError("Lua文字列末尾のescapeが不正です")
        token = value[index]
        if token.isdigit():
            match = re.match(r"[0-9]{1,3}", value[index:])
            if match is None:
                raise ValueError("10進escapeが不正です")
            number = int(match.group(0))
            if number > 255:
                raise ValueError("10進escapeがbyte範囲外です")
            output.append(number)
            index += len(match.group(0))
            continue
        if token == "x":
            raw = value[index + 1 : index + 3]
            if len(raw) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", raw):
                raise ValueError("16進escapeが不正です")
            output.append(int(raw, 16))
            index += 3
            continue
        index += 1
        if token in simple:
            output.append(simple[token])
        elif token == "\r":
            if index < len(value) and value[index] == "\n":
                index += 1
        elif token == "\n":
            continue
        else:
            raise ValueError("未対応のLua escapeです")
        if len(output) > MAX_LITERAL_SIZE:
            raise ValueError("Lua文字列が上限を超えています")
    return bytes(output)


def _local_strings(
    text: str,
    *,
    budget: _QuoteScanBudget,
) -> list[tuple[str, bytes]]:
    values: list[tuple[str, bytes]] = []
    candidate_count = 0
    decoded_total = 0
    for match in LOCAL_ASSIGNMENT.finditer(text):
        candidate_count += 1
        if candidate_count > MAX_LOCAL_ASSIGNMENT_CANDIDATES:
            raise RecoveryLimitError("Lua local assignment候補が上限を超えています")
        opening = match.end()
        if opening >= len(text) or text[opening] not in {'"', "'"}:
            continue
        try:
            closing = _quoted_end(text, opening, end=len(text), budget=budget)
            decoded = _decode_lua_string(text[opening + 1 : closing])
        except QuoteScanLimitError:
            raise
        except ValueError:
            continue
        decoded_total += len(decoded)
        if decoded_total > MAX_DECODED_LITERAL_BYTES:
            raise RecoveryLimitError("Lua文字列の累積復元量が上限を超えています")
        values.append((match.group(1), decoded))
    return values


def _single_byte_cells(
    body: str,
    *,
    budget: _QuoteScanBudget,
) -> list[int] | None:
    values: list[int] = []
    index = 0
    while index < len(body):
        while index < len(body) and (body[index].isspace() or body[index] in ",;"):
            index += 1
        if index == len(body):
            break
        if body[index] not in {'"', "'"}:
            return None
        try:
            closing = _quoted_end(body, index, end=len(body), budget=budget)
            decoded = _decode_lua_string(body[index + 1 : closing])
        except QuoteScanLimitError:
            raise
        except ValueError:
            return None
        if len(decoded) != 1 or not 33 <= decoded[0] <= 126:
            return None
        values.append(decoded[0])
        index = closing + 1
    return values


def _table_rows(
    text: str,
    opening: int,
    closing: int,
    *,
    budget: _QuoteScanBudget,
) -> list[bytes] | None:
    rows: list[bytes] = []
    depth = 0
    start: int | None = None
    index = opening
    while index <= closing:
        value = text[index]
        if value in {'"', "'"}:
            try:
                index = _quoted_end(text, index, end=closing + 1, budget=budget) + 1
            except QuoteScanLimitError:
                raise
            except ValueError:
                return None
            continue
        if value == "{":
            depth += 1
            if depth == 2:
                start = index + 1
            elif depth > 2:
                return None
        elif value == "}":
            if depth == 2 and start is not None:
                cells = _single_byte_cells(text[start:index], budget=budget)
                if cells is None or len(cells) != 10 or len(set(cells)) != 10:
                    return None
                rows.append(bytes(cells))
                start = None
            depth -= 1
        index += 1
    if depth != 0 or len(rows) != 25:
        return None
    return rows


def _source_tables(
    text: str,
    *,
    budget: _QuoteScanBudget,
) -> tuple[list[tuple[str, list[bytes]]], bool, int]:
    tables: list[tuple[str, list[bytes]]] = []
    candidate_count = 0
    for match in SOURCE_TABLE.finditer(text):
        candidate_count += 1
        if candidate_count > MAX_TABLE_CANDIDATES:
            return tables, False, candidate_count
        opening = text.find("{", match.start())
        try:
            closing = _matching_brace(
                text,
                opening,
                max_span=MAX_TABLE_SIZE,
                budget=budget,
            )
        except QuoteScanLimitError:
            raise
        except (RecoveryLimitError, ValueError):
            continue
        if closing - opening > MAX_TABLE_SIZE:
            continue
        rows = _table_rows(text, opening, closing, budget=budget)
        if rows is not None:
            tables.append((match.group(1), rows))
    return tables, True, candidate_count


def _target_table_present(
    text: str,
    *,
    budget: _QuoteScanBudget,
) -> tuple[bool, bool, int]:
    candidate_count = 0
    for match in LOCAL_ASSIGNMENT.finditer(text):
        candidate_count += 1
        if candidate_count > MAX_LOCAL_ASSIGNMENT_CANDIDATES:
            return False, False, candidate_count
        opening = match.end()
        if opening >= len(text) or text[opening] != "{":
            continue
        try:
            closing = _matching_brace(text, opening, max_span=1024, budget=budget)
        except QuoteScanLimitError:
            raise
        except (RecoveryLimitError, ValueError):
            continue
        if closing - opening > 1024:
            continue
        cells = _single_byte_cells(text[opening + 1 : closing], budget=budget)
        if cells is not None and bytes(cells) == TARGET_ALPHABET:
            return True, True, candidate_count
    return False, True, candidate_count


def _selector(value: bytes) -> int:
    if len(value) < 2 or value[0] != ord("|"):
        raise ValueError("置換表selectorがありません")
    token = value[1]
    if ord("0") <= token <= ord("9"):
        return token - ord("0")
    if ord("A") <= token <= ord("O"):
        return 10 + token - ord("A")
    raise ValueError("置換表selectorが範囲外です")


def recover_bytes(data: bytes) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """Luaコードを実行せず、混在表記の25行置換表を使うDonut層を復元する。"""

    base_report: dict[str, object] = {
        "schema_version": 1,
        "handler": "luajit_polyrot_mixed_table",
        "input_sha256": _sha256(data),
        "input_size": len(data),
        "executed": False,
        "network_contacted": False,
    }
    if len(data) > MAX_SCRIPT_SIZE:
        return {**base_report, "status": "size_blocked"}, []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {**base_report, "status": "not_utf8"}, []

    quote_scan_budget = _QuoteScanBudget(MAX_TOTAL_QUOTED_SCAN_CHARS)
    try:
        local_strings = _local_strings(text, budget=quote_scan_budget)
    except RecoveryLimitError:
        return {
            **base_report,
            "status": "candidate_limit_exceeded",
            "candidate_set_complete": False,
            "candidate_set_truncated": True,
        }, []
    payload_literals = [
        (name, value)
        for name, value in local_strings
        if len(value) >= MIN_PAYLOAD_SIZE
        and value[:1] == b"|"
        and value[1:2]
        in tuple(bytes([item]) for item in range(ord("0"), ord("9") + 1))
        + tuple(bytes([item]) for item in range(ord("A"), ord("O") + 1))
    ]
    if not payload_literals:
        return {**base_report, "status": "pattern_not_found"}, []
    if len(payload_literals) > MAX_PAYLOAD_LITERALS:
        return {**base_report, "status": "candidate_limit_exceeded"}, []
    if ":reverse()" not in text or ":sub(1,1)" not in text:
        return {**base_report, "status": "semantic_anchor_missing"}, []
    if not any(value == BASE64_ALPHABET for _, value in local_strings):
        return {**base_report, "status": "base64_alphabet_missing"}, []
    try:
        target_present, target_complete, target_candidate_count = _target_table_present(
            text,
            budget=quote_scan_budget,
        )
    except QuoteScanLimitError:
        return {
            **base_report,
            "status": "candidate_limit_exceeded",
            "candidate_set_complete": False,
            "candidate_set_truncated": True,
        }, []
    if not target_complete:
        return {
            **base_report,
            "status": "candidate_limit_exceeded",
            "candidate_set_complete": False,
            "candidate_set_truncated": True,
            "target_table_candidate_count_lower_bound": target_candidate_count,
        }, []
    if not target_present:
        return {**base_report, "status": "target_alphabet_missing"}, []

    try:
        tables, table_candidates_complete, table_candidate_count = _source_tables(
            text,
            budget=quote_scan_budget,
        )
    except QuoteScanLimitError:
        return {
            **base_report,
            "status": "candidate_limit_exceeded",
            "candidate_set_complete": False,
            "candidate_set_truncated": True,
        }, []
    if not table_candidates_complete:
        return {
            **base_report,
            "status": "candidate_limit_exceeded",
            "candidate_set_complete": False,
            "candidate_set_truncated": True,
            "source_table_candidate_count_lower_bound": table_candidate_count,
            "source_table_count": len(tables),
        }, []
    recovered: dict[str, tuple[bytes, dict[str, object]]] = {}
    attempts = 0
    rejected = 0
    transform_work_bytes = 0
    for variable, literal in payload_literals:
        try:
            row_index = _selector(literal)
        except ValueError:
            rejected += 1
            continue
        body = literal[2:]
        if len(body) > MAX_LITERAL_SIZE or len(body) % 4:
            rejected += 1
            continue
        observed_symbols = set(body) - BASE64_ALLOWED
        if len(observed_symbols) != 10:
            rejected += 1
            continue
        for table_variable, rows in tables:
            source = rows[row_index]
            if set(source) != observed_symbols:
                continue
            attempts += 1
            if attempts > MAX_TRANSFORM_ATTEMPTS:
                return {
                    **base_report,
                    "status": "attempt_limit_exceeded",
                    "candidate_set_complete": False,
                    "candidate_set_truncated": True,
                    "payload_literal_count": len(payload_literals),
                    "source_table_count": len(tables),
                    "attempt_count_lower_bound": attempts,
                    "transform_work_bytes": transform_work_bytes,
                }, []
            estimated_work = len(body) * 3
            if transform_work_bytes + estimated_work > MAX_TOTAL_TRANSFORM_BYTES:
                return {
                    **base_report,
                    "status": "transform_work_limit_exceeded",
                    "candidate_set_complete": False,
                    "candidate_set_truncated": True,
                    "payload_literal_count": len(payload_literals),
                    "source_table_count": len(tables),
                    "attempt_count": attempts,
                    "transform_work_bytes": transform_work_bytes,
                }, []
            transform_work_bytes += estimated_work
            translated = body.translate(bytes.maketrans(source, TARGET_ALPHABET))[::-1]
            try:
                rotated = base64.b64decode(translated, validate=True)
                payload = inverse_polyrot(rotated)
            except (ValueError, binascii.Error):
                rejected += 1
                continue
            if not is_donut_shellcode(payload):
                rejected += 1
                continue
            digest = _sha256(payload)
            recovered[digest] = (
                payload,
                {
                    "variable": variable,
                    "table_variable": table_variable,
                    "table_row": row_index,
                    "header": literal[:2].decode("ascii"),
                    "source_alphabet_sha256": _sha256(source),
                    "encoded_size": len(body),
                    "polyrot_size": len(rotated),
                    "sha256": digest,
                    "size": len(payload),
                    "artifact_kind": "donut_shellcode",
                },
            )

    if not recovered:
        return {
            **base_report,
            "status": "strict_validation_failed",
            "payload_literal_count": len(payload_literals),
            "source_table_count": len(tables),
            "attempt_count": attempts,
            "rejected_count": rejected,
            "transform_work_bytes": transform_work_bytes,
            "candidate_set_complete": True,
            "candidate_set_truncated": False,
        }, []
    payloads = [value[1] for _, value in sorted(recovered.items())]
    artifacts = [
        ("luajit-polyrot-mixed-table-donut-shellcode", value[0])
        for _, value in sorted(recovered.items())
    ]
    return {
        **base_report,
        "status": "donut_shellcode_recovered",
        "payload_literal_count": len(payload_literals),
        "source_table_count": len(tables),
        "attempt_count": attempts,
        "rejected_count": rejected,
        "transform_work_bytes": transform_work_bytes,
        "candidate_set_complete": True,
        "candidate_set_truncated": False,
        "payloads": payloads,
    }, artifacts
