"""反転・区切り文字挿入・Base64型JavaScriptドロッパーを静的に復元する。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

import pefile

from unpackers.javascript_obfuscator import decode_script_text


MAX_SCRIPT_SIZE = 256 * 1024 * 1024
MAX_LITERAL_SIZE = 128 * 1024 * 1024
MAX_DECODED_SIZE = 256 * 1024 * 1024
MIN_LITERAL_SIZE = 4096
BASE64_CHARACTER = re.compile(r"[A-Za-z0-9+/=]")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_javascript_string(raw: str) -> str:
    """限定したJavaScript文字列エスケープだけを解釈する。"""
    output: list[str] = []
    index = 0
    simple = {
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "0": "\0",
    }
    while index < len(raw):
        value = raw[index]
        if value != "\\":
            output.append(value)
            index += 1
            continue
        index += 1
        if index >= len(raw):
            raise ValueError("JavaScript文字列の末尾が不正です")
        token = raw[index]
        index += 1
        if token in "\\\"'":
            output.append(token)
        elif token in simple:
            output.append(simple[token])
        elif token == "x":
            if index + 2 > len(raw):
                raise ValueError("\\xエスケープが不完全です")
            output.append(chr(int(raw[index : index + 2], 16)))
            index += 2
        elif token == "u":
            if index + 4 > len(raw):
                raise ValueError("\\uエスケープが不完全です")
            output.append(chr(int(raw[index : index + 4], 16)))
            index += 4
        elif token in "\r\n":
            if token == "\r" and index < len(raw) and raw[index] == "\n":
                index += 1
        else:
            output.append(token)
    return "".join(output)


def _string_literals(text: str):
    """コメントを実行せず、引用符で囲まれた文字列を前方走査する。"""
    index = 0
    while index < len(text):
        quote = text[index]
        if quote not in {"'", '"'}:
            index += 1
            continue
        start = index
        index += 1
        content_start = index
        escaped = False
        while index < len(text):
            value = text[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if value == "\\":
                escaped = True
                index += 1
                continue
            if value == quote:
                raw = text[content_start:index]
                yield start, raw
                index += 1
                break
            index += 1
        else:
            return


def _valid_pe(data: bytes) -> bool:
    if not data.startswith(b"MZ"):
        return False
    try:
        image = pefile.PE(data=data, fast_load=True)
        return 1 <= image.FILE_HEADER.NumberOfSections <= 96
    except (AttributeError, ValueError, pefile.PEFormatError):
        return False


def _artifact_kind(data: bytes) -> str | None:
    if _valid_pe(data):
        return "pe"
    if len(data) > MAX_LITERAL_SIZE:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    anchors = (
        text.lstrip().startswith("local "),
        "PolyRot" in text,
        'require("\\102\\102\\105")' in text or 'require("ffi")' in text,
        "NtAllocateVirtualMemory" in text,
        "RtlMoveMemory" in text,
    )
    return "lua" if sum(anchors) >= 3 else None


def recover_reverse_base64(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """長大文字列を反転し、Base64外の区切り文字を除去して復元する。"""
    if len(data) > MAX_SCRIPT_SIZE:
        return {"status": "size_blocked", "executed": False}, []
    text = decode_script_text(data)
    artifacts: list[tuple[str, bytes]] = []
    candidates: list[dict[str, object]] = []
    seen: set[str] = set()
    inspected = 0
    for offset, raw in _string_literals(text):
        if not MIN_LITERAL_SIZE <= len(raw) <= MAX_LITERAL_SIZE:
            continue
        inspected += 1
        try:
            literal = _decode_javascript_string(raw)
        except (UnicodeError, ValueError):
            continue
        reversed_value = literal[::-1]
        compact = "".join(BASE64_CHARACTER.findall(reversed_value))
        if len(compact) < 1024 or len(compact) / max(1, len(reversed_value)) < 0.20:
            continue
        if len(compact) % 4:
            continue
        try:
            decoded = base64.b64decode(compact, validate=True)
        except (ValueError, binascii.Error):
            continue
        if not 1 <= len(decoded) <= MAX_DECODED_SIZE:
            continue
        kind = _artifact_kind(decoded)
        if kind is None:
            continue
        digest = _sha256(decoded)
        candidates.append(
            {
                "literal_offset": offset,
                "literal_size": len(literal),
                "base64_size": len(compact),
                "separator_characters": sorted(set(reversed_value) - set(compact)),
                "decoded_kind": kind,
                "decoded_size": len(decoded),
                "decoded_sha256": digest,
            }
        )
        if digest in seen:
            continue
        seen.add(digest)
        artifacts.append((f"javascript-reverse-base64-{kind}", decoded))
    return (
        {
            "status": "artifacts_recovered" if artifacts else "pattern_not_found",
            "large_literals_inspected": inspected,
            "candidates": candidates,
            "executed": False,
            "network_contacted": False,
        },
        artifacts,
    )
