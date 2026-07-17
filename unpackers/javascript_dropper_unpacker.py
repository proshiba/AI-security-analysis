"""Statically recover Unicode-array JavaScript dropper payloads.

Only narrowly recognized integer expressions, array concatenation, character
mapping, AES-CBC, and GZip recipes are interpreted. JavaScript and PowerShell
are never executed.
"""

from __future__ import annotations

import ast
import gzip
import io
import re

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import pefile

from unpackers.javascript_obfuscator import decode_script_text

_MAX_REBUILT = 256 * 1024 * 1024

_BINARY = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    ast.BitXor: lambda a, b: a ^ b,
    ast.BitOr: lambda a, b: a | b,
    ast.BitAnd: lambda a, b: a & b,
    ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b,
}
_UNARY = {
    ast.UAdd: lambda value: value,
    ast.USub: lambda value: -value,
    ast.Invert: lambda value: ~value,
}


def _safe_integer(expression: str) -> int:
    """Evaluate one integer-only expression from an obfuscated array."""

    def visit(node: ast.AST) -> int | float:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
            return _BINARY[type(node.op)](visit(node.left), visit(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
            return _UNARY[type(node.op)](visit(node.operand))
        raise ValueError("unsupported integer expression")

    return int(visit(ast.parse(expression.strip(), mode="eval")))


def _integer_array(body: str) -> list[int]:
    """Parse a comma-separated array of bounded constant expressions."""
    parts = [item for item in body.split(",") if item.strip()]
    if not 1 <= len(parts) <= 16 * 1024 * 1024:
        raise ValueError("integer array size blocked")
    return [_safe_integer(item) for item in parts]


def _literal(text: str, name: str) -> str | None:
    match = re.search(r"\bvar\s+" + re.escape(name) + r'\s*=\s*"([^"]*)"', text)
    return match.group(1) if match else None


def _decode_xor_concat(text: str) -> tuple[bytes, str] | None:
    """Decode the object-array concatenation plus repeating-key XOR pattern."""
    arrays: dict[tuple[str, str], list[int]] = {}
    for match, body in _array_assignments(
        text, r'(?<![\w$])([A-Za-z_$][\w$]{0,127})\["([^"\r\n]{1,256})"\]\s*=\s*\['
    ):
        try:
            arrays[(match.group(1), match.group(2))] = _integer_array(body)
        except (SyntaxError, ValueError, ZeroDivisionError):
            continue
    best: list[tuple[str, str]] = []
    for line in text.splitlines():
        if ".concat(" not in line:
            continue
        references = re.findall(r'(\w+)\["([^"]+)"\]', line)
        if len(references) > len(best) and all(item in arrays for item in references):
            best = references
    key_options = [
        (match, _literal(text, match.group(1)))
        for match in re.finditer(
            r"\^\s*\((\w+)\.charCodeAt\([^)]*\)\s*-\s*(\d+)\)", text
        )
    ]
    key_options = [(match, key) for match, key in key_options if key]
    if len(best) < 2 or not key_options:
        return None
    key_match, key = key_options[-1]
    base = int(key_match.group(2))
    values = [value for reference in best for value in arrays[reference]]
    decoded = bytes(
        (value ^ (ord(key[index % len(key)]) - base)) & 0xFF
        for index, value in enumerate(values)
    )
    return decoded, "object_array_repeating_xor"


def _decode_subtract_array(text: str) -> tuple[bytes, str] | None:
    """Decode one large numeric array with a repeating Unicode subtraction key."""
    key_match = re.search(
        r"-\s*\((\w+)\.charCodeAt\([^)]*\)\s*-\s*(\d+)\)\s*\+\s*256",
        text,
    )
    if not key_match:
        return None
    key, base = _literal(text, key_match.group(1)), int(key_match.group(2))
    if not key:
        return None
    candidates = _array_assignments(text, r"\bvar\s+(\w+)\s*=\s*\[")
    candidates.sort(key=lambda item: len(item[1]), reverse=True)
    for _match, body in candidates:
        if len(body) < 1024:
            continue
        try:
            values = _integer_array(body)
        except (SyntaxError, ValueError, ZeroDivisionError):
            continue
        decoded = bytes(
            (value - (ord(key[index % len(key)]) - base) + 256) & 0xFF
            for index, value in enumerate(values)
        )
        return decoded, "numeric_array_repeating_subtraction"
    return None


def _environment_payload(text: str, powershell: str) -> tuple[dict, bytes | None]:
    """Rebuild PowerShell's environment-variable byte stream and transforms."""
    values = {
        match.group(1): match.group(2)
        for match in re.finditer(r'\w+\("([A-Za-z0-9]+)"\)\s*=\s*"([^"]*)";', text)
    }
    values.update(
        {
            match.group(1): match.group(2)
            for match in re.finditer(
                r'\w+\["[^"]+"\]\s*=\s*\["([A-Za-z0-9]+)",\s*"([^"]*)"\];',
                text,
            )
        }
    )
    aggregations = []
    for match in re.finditer(r"\$\w+\s*=\s*\((.*?)\);", powershell, re.S):
        names = re.findall(r"\$env:([A-Za-z0-9]+)", match.group(1), re.I)
        if names:
            aggregations.append(names)
    if not aggregations:
        return {"status": "environment_aggregation_not_found"}, None
    names = max(aggregations, key=len)
    missing = [name for name in names if name not in values]
    if missing:
        return {
            "status": "environment_chunks_missing",
            "referenced_chunks": len(names),
            "missing_chunks": missing[:32],
        }, None
    joined = "".join(values[name] for name in names)
    if not joined or len(joined) > _MAX_REBUILT:
        return {"status": "environment_size_blocked"}, None
    if any(not 0 <= ord(character) - 19968 <= 255 for character in joined):
        return {"status": "environment_character_range_invalid"}, None
    payload = bytes(ord(character) - 19968 for character in joined)
    transforms = ["unicode_minus_19968"]
    if "AesManaged" in powershell:
        key_match = re.search(r"\.Key=\[byte\[\]\]@\(([^)]*)\)", powershell)
        iv_match = re.search(r"\.IV=\[byte\[\]\]@\(([^)]*)\)", powershell)
        if not key_match or not iv_match:
            return {"status": "aes_parameters_missing", "chunks": len(names)}, None
        try:
            key = bytes(_integer_array(key_match.group(1)))
            iv = bytes(_integer_array(iv_match.group(1)))
        except ValueError:
            return {"status": "aes_parameters_invalid", "chunks": len(names)}, None
        if len(key) not in {16, 24, 32} or len(iv) != AES.block_size:
            return {"status": "aes_parameters_invalid", "chunks": len(names)}, None
        if len(payload) % AES.block_size:
            return {"status": "aes_ciphertext_misaligned", "chunks": len(names)}, None
        try:
            payload = unpad(
                AES.new(key, AES.MODE_CBC, iv).decrypt(payload), AES.block_size
            )
        except ValueError:
            return {"status": "aes_decryption_failed", "chunks": len(names)}, None
        transforms.append("aes_cbc_pkcs7")
    if "GZipStream" in powershell:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
                payload = stream.read(_MAX_REBUILT + 1)
        except (EOFError, OSError):
            return {"status": "gzip_decompression_failed", "chunks": len(names)}, None
        if len(payload) > _MAX_REBUILT:
            return {"status": "gzip_size_blocked", "chunks": len(names)}, None
        transforms.append("gzip")
    return {
        "status": "payload_rebuilt",
        "chunks": len(names),
        "transforms": transforms,
        "payload_size": len(payload),
    }, payload


def _is_valid_pe(data: bytes) -> bool:
    try:
        image = pefile.PE(data=data, fast_load=True)
        return data.startswith(b"MZ") and 1 <= image.FILE_HEADER.NumberOfSections <= 96
    except (AttributeError, pefile.PEFormatError, ValueError):
        return False


def recover_javascript_dropper(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """Recover recognized JavaScript, PowerShell, and final PE layers statically."""
    text = decode_script_text(data)
    stage = _decode_xor_concat(text) or _decode_subtract_array(text)
    if not stage:
        return {"status": "pattern_not_found", "executed": False}, []
    powershell_bytes, pattern = stage
    try:
        powershell = powershell_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "status": "decoded_stage_not_utf8",
            "pattern": pattern,
            "executed": False,
        }, []
    artifacts = [("javascript-decoded-powershell", powershell_bytes)]
    try:
        payload_report, payload = _environment_payload(text, powershell)
    except (SyntaxError, ValueError, ZeroDivisionError):
        payload_report, payload = {"status": "transform_expression_invalid"}, None
    if payload is not None and _is_valid_pe(payload):
        transforms = "-".join(payload_report["transforms"])
        artifacts.append((f"javascript-{transforms}-pe", payload))
        status = "pe_recovered"
    elif payload is not None:
        payload_report["status"] = "rebuilt_payload_not_pe"
        status = "powershell_recovered"
    else:
        status = "powershell_recovered"
    return {
        "status": status,
        "pattern": pattern,
        "powershell_size": len(powershell_bytes),
        "payload": payload_report,
        "executed": False,
    }, artifacts


def _array_assignments(text: str, header_pattern: str) -> list[tuple[re.Match[str], str]]:
    """Return bracket-bounded array assignments with one forward-only scan."""
    pattern = re.compile(header_pattern)
    results: list[tuple[re.Match[str], str]] = []
    cursor = 0
    while cursor < len(text):
        match = pattern.search(text, cursor)
        if not match:
            break
        close = text.find("]", match.end())
        if close < 0:
            break
        trailer = close + 1
        while trailer < len(text) and text[trailer].isspace():
            trailer += 1
        if trailer < len(text) and text[trailer] == ";":
            results.append((match, text[match.end():close]))
        cursor = close + 1
    return results
