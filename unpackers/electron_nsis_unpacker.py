"""梱包されたJavaScriptやPEを実行せずElectron NSIS payloadを静的復元する。"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path, PurePosixPath

import pefile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from unpackers.asar_unpacker import asar_header, is_asar, recover_asar
from unpackers.javascript_obfuscator import _fold_literal_additions, decode_script_text
from unpackers.path_safety import safe_member_name
from unpackers.static_unpacker import (
    MAX_STATIC_TOOL_TEMP_BYTES,
    MAX_STATIC_TOOL_TEMP_ENTRIES,
    StaticToolExecutionError,
    _read_static_tool_output,
    _run_static_tool_process,
)

MAX_ARCHIVE = 256 * 1024 * 1024
MAX_ASAR = 64 * 1024 * 1024
MAX_MEMBERS = 512
MAX_ASAR_DEPTH = 64
MAX_ASAR_CONTAINER_NODES = 2048
MAX_SCRIPT = 2 * 1024 * 1024
MAX_ELECTRON_SCRIPTS = 64
MAX_ELECTRON_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_CIPHERTEXT = 64 * 1024 * 1024
MAX_TERMINAL_PE = 64 * 1024 * 1024
MAX_JS_ARRAY = 10_000
MAX_JS_VALUE = 65_536
MAX_JS_ROTATION = 100_000
MAX_PE_IMPORT_DESCRIPTORS = 256
MAX_PE_IMPORT_SYMBOLS_PER_DLL = 2_048
MAX_PE_STRING_SCAN = 8 * 1024 * 1024
MAX_PE_STRINGS_PER_ENCODING = 4_096
_STANDARD_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _safe_integer(expression: str, names: dict[str, int] | None = None) -> int:
    """観測済み難読化器が生成する整数式の部分集合だけを安全に評価する。"""
    if len(expression) > 256:
        raise ValueError("integer expression exceeds bounds")
    known = names or {}
    binary = {
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.Mod: lambda a, b: a % b,
        ast.BitXor: lambda a, b: a ^ b,
        ast.BitOr: lambda a, b: a | b,
        ast.BitAnd: lambda a, b: a & b,
        ast.LShift: lambda a, b: a << b,
        ast.RShift: lambda a, b: a >> b,
    }

    def visit(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            if not -(1 << 63) <= node.value <= (1 << 63):
                raise ValueError("integer literal exceeds bounds")
            return node.value
        if isinstance(node, ast.Name) and node.id in known:
            value = known[node.id]
            if not isinstance(value, int) or not -(1 << 67) <= value <= (1 << 67):
                raise ValueError("named integer exceeds bounds")
            return value
        if isinstance(node, ast.BinOp) and type(node.op) in binary:
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, (ast.LShift, ast.RShift)) and not 0 <= right <= 63:
                raise ValueError("shift count exceeds bounds")
            value = binary[type(node.op)](left, right)
        elif isinstance(node, ast.UnaryOp) and isinstance(
            node.op, (ast.UAdd, ast.USub)
        ):
            operand = visit(node.operand)
            value = operand if isinstance(node.op, ast.UAdd) else -operand
        else:
            raise ValueError("unsupported integer syntax")
        if not -(1 << 63) <= value <= (1 << 63):
            raise ValueError("integer result exceeds bounds")
        return value

    return visit(ast.parse(expression, mode="eval"))


def _matching_delimiter(text: str, start: int, opening: str, closing: str) -> int:
    """引用済みJavaScript文字列を無視し、対応する終端delimiterを探す。"""
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
        elif character in {'"', "'"}:
            quote = character
        elif character == opening:
            depth += 1
        elif character == closing:
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unmatched JavaScript delimiter")


def _split_arguments(text: str) -> list[str]:
    """式だけから成る上限付きJavaScript引数列を分割する。"""
    output: list[str] = []
    start, depth = 0, 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            output.append(text[start:index])
            start = index + 1
    output.append(text[start:])
    return output


def _rc4_bytes(data: bytes, key: bytes) -> bytes:
    """難読化文字列token 1個へ上限付きRC4変換を適用する。"""
    if not 8 <= len(key) <= 64 or len(data) > MAX_JS_VALUE:
        raise ValueError("RC4 input exceeds bounds")
    box = list(range(256))
    position = 0
    for index in range(256):
        position = (position + box[index] + key[index % len(key)]) & 0xFF
        box[index], box[position] = box[position], box[index]
    left = position = 0
    output = bytearray()
    for value in data:
        left = (left + 1) & 0xFF
        position = (position + box[left]) & 0xFF
        box[left], box[position] = box[position], box[left]
        output.append(value ^ box[(box[left] + box[position]) & 0xFF])
    return bytes(output)


def deobfuscate_generated_alphabet_rc4(data: bytes) -> tuple[dict, bytes | None]:
    """JavaScriptを実行せず、生成alphabet/RC4文字列配列を復号する。"""
    if not 0 < len(data) <= MAX_SCRIPT:
        return {"status": "script_size_blocked", "executed": False}, None
    text = decode_script_text(data)
    alphabet_match = re.search(r'var\s+(?P<alpha>_0x[0-9a-f]+)="";', text)
    if not alphabet_match:
        return {"status": "pattern_not_found", "executed": False}, None
    alphabet_name = alphabet_match.group("alpha")
    alphabet_window = text[alphabet_match.end() : alphabet_match.end() + 2500]
    loops = list(
        re.finditer(
            rf"for\(var\s+(?P<i>_0x[0-9a-f]+)=(?P<start>[^;]+);(?P=i)<(?P<end>[^;]+);(?P=i)\+\+\)"
            rf"{re.escape(alphabet_name)}\+=String\.fromCharCode\((?P=i)\);",
            alphabet_window,
        )
    )
    if len(loops) != 3:
        return {"status": "alphabet_loops_missing", "executed": False}, None
    alphabet = ""
    try:
        for loop in loops:
            start, end = (
                _safe_integer(loop.group("start")),
                _safe_integer(loop.group("end")),
            )
            if not 0 <= start <= end <= 256 or end - start > 128:
                raise ValueError("alphabet range exceeds bounds")
            alphabet += "".join(chr(value) for value in range(start, end))
        suffix_offset = loops[-1].end()
        suffix_match = re.match(
            rf"{re.escape(alphabet_name)}\+=String\.fromCharCode\((?P<args>[^;]+)\);",
            alphabet_window[suffix_offset:],
        )
        if not suffix_match:
            raise ValueError("alphabet suffix missing")
        alphabet += "".join(
            chr(_safe_integer(argument))
            for argument in _split_arguments(suffix_match.group("args"))
        )
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "alphabet_invalid", "executed": False}, None
    if (
        len(alphabet) != 65
        or set(alphabet) != set(_STANDARD_BASE64)
        or alphabet[-1] != "="
    ):
        return {"status": "alphabet_invalid", "executed": False}, None

    arrays: list[tuple[int, str, list[str], int]] = []
    for match in re.finditer(
        r"function\s+(?P<name>_0x[0-9a-f]+)\(\)\{var\s+_0x[0-9a-f]+=\[", text
    ):
        start = text.find("[", match.end() - 1)
        try:
            end = _matching_delimiter(text, start, "[", "]")
            values = ast.literal_eval(text[start : end + 1])
        except (ValueError, SyntaxError):
            continue
        if (
            isinstance(values, list)
            and values
            and all(isinstance(value, str) for value in values)
        ):
            arrays.append((len(values), match.group("name"), values, end))
    if not arrays:
        return {"status": "array_missing", "executed": False}, None
    _, array_name, values, array_end = max(arrays)
    if len(values) > MAX_JS_ARRAY or any(len(value) > MAX_JS_VALUE for value in values):
        return {"status": "array_blocked", "executed": False}, None

    accumulator_match = re.search(
        rf"var\s+(?P<acc>_0x[0-9a-f]+)=(?P<initial>[^,;]+),(?P<arr>_0x[0-9a-f]+)={re.escape(array_name)}\(\);"
        rf".*?(?P=acc)=\((?P=acc)\+(?P<char>_0x[0-9a-f]+)\.charCodeAt\([^)]*\)\)%(?P<mod>[^}};]+)",
        text[:array_end],
        re.DOTALL,
    )
    if not accumulator_match:
        return {
            "status": "key_accumulator_missing",
            "array_function": array_name,
            "array_end": array_end,
            "executed": False,
        }, None
    try:
        if _safe_integer(accumulator_match.group("mod")) != 256:
            raise ValueError("unexpected accumulator modulus")
        accumulator = _safe_integer(accumulator_match.group("initial"))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "key_accumulator_invalid", "executed": False}, None
    for value in values:
        for character in value:
            accumulator = (accumulator + ord(character)) & 0xFF
    key_match = None
    for candidate in re.finditer(
        r"var\s+(?P<key>_0x[0-9a-f]+)=String\.fromCharCode\((?P<args>.*?)\);function",
        text[:array_end],
        re.DOTALL,
    ):
        arguments = _split_arguments(candidate.group("args"))
        if 8 <= len(arguments) <= 64 and all(
            accumulator_match.group("acc") in item for item in arguments
        ):
            key_match = candidate
    if key_match is None:
        return {"status": "key_expression_missing", "executed": False}, None
    try:
        rc4_key = bytes(
            _safe_integer(argument, {accumulator_match.group("acc"): accumulator})
            & 0xFF
            for argument in _split_arguments(key_match.group("args"))
        )
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "key_expression_invalid", "executed": False}, None

    rotation_match = re.search(
        rf"\)\({re.escape(array_name)},(?P<count>[0-9+\-^&|<> ]+)\);",
        text[array_end : array_end + 3000],
    )
    if not rotation_match:
        return {"status": "rotation_missing", "executed": False}, None
    try:
        rotation_count = _safe_integer(rotation_match.group("count"))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "rotation_invalid", "executed": False}, None
    if not 1 <= rotation_count <= MAX_JS_ROTATION:
        return {"status": "rotation_blocked", "executed": False}, None
    rotation = (rotation_count - 1) % len(values)
    rotated = values[rotation:] + values[:rotation]

    accessor_match = re.search(
        rf"function\s+(?P<name>_0x[0-9a-f]+)\((?P<arg>_0x[0-9a-f]+)\)\{{(?P=arg)=(?P=arg)-\((?P<offset>[^;]+)\);"
        rf".*?{re.escape(array_name)}\(\)\[(?P=arg)\]",
        text[array_end:],
        re.DOTALL,
    )
    if not accessor_match:
        return {"status": "accessor_missing", "executed": False}, None
    try:
        offset = _safe_integer(accessor_match.group("offset"))
    except (SyntaxError, ValueError, ZeroDivisionError):
        return {"status": "accessor_offset_invalid", "executed": False}, None
    accessor = accessor_match.group("name")
    wrappers = {accessor: 0}
    for wrapper in re.finditer(
        rf"function\s+(?P<name>_0x[0-9a-f]+)\((?P<arg>_0x[0-9a-f]+)\)\{{return\s+{re.escape(accessor)}\((?P=arg)-\((?P<delta>[^)]+)\)\)\}}",
        text[array_end:],
    ):
        try:
            wrappers[wrapper.group("name")] = _safe_integer(wrapper.group("delta"))
        except (SyntaxError, ValueError, ZeroDivisionError):
            continue
    translation = str.maketrans(alphabet, _STANDARD_BASE64)
    cache: dict[int, str] = {}

    def decode(index: int) -> str:
        if index not in cache:
            if not 0 <= index < len(rotated):
                raise ValueError("decoded index outside array")
            token = rotated[index].translate(translation)
            token += "=" * (-len(token) % 4)
            raw = base64.b64decode(token, validate=True)
            cache[index] = _rc4_bytes(raw, rc4_key).decode("utf-8")
        return cache[index]

    call_pattern = re.compile(
        r"\b("
        + "|".join(map(re.escape, sorted(wrappers, key=len, reverse=True)))
        + r")\(([^()]*)\)"
    )
    substitutions = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal substitutions
        try:
            argument = _safe_integer(match.group(2))
            value = decode(argument - wrappers[match.group(1)] - offset)
        except (SyntaxError, ValueError, UnicodeDecodeError, ZeroDivisionError):
            return match.group()
        substitutions += 1
        return json.dumps(value, ensure_ascii=False)

    transformed = _fold_literal_additions(call_pattern.sub(replace, text)).encode(
        "utf-8"
    )
    return {
        "status": "deobfuscated",
        "array_size": len(values),
        "rotation": rotation,
        "decoder_offset": offset,
        "wrapper_count": len(wrappers),
        "substitutions": substitutions,
        "executed": False,
    }, transformed


def _defang_url(value: str) -> str:
    """抽出URL 1件をレポート用に無害化して表現する。"""
    return re.sub(
        r"^https?",
        lambda match: "hxxps" if match.group().lower() == "https" else "hxxp",
        value,
        flags=re.IGNORECASE,
    ).replace(".", "[.]")


def electron_asar_preflight(data: bytes) -> dict:
    """Electron専用size/member上限をblob抽出前に検証する。"""
    if not 1 <= len(data) <= MAX_ASAR:
        return {
            "status": "asar_size_blocked",
            "size": len(data),
            "maximum_size": MAX_ASAR,
            "sample_executed": False,
        }
    try:
        header, _ = asar_header(data)
        count = 0
        containers = 0
        stack: list[tuple[str, dict, int]] = [("", header["files"], 1)]
        while stack:
            prefix, tree, depth = stack.pop()
            containers += 1
            if depth > MAX_ASAR_DEPTH or containers > MAX_ASAR_CONTAINER_NODES:
                return {
                    "status": "asar_tree_limit_blocked",
                    "maximum_depth": MAX_ASAR_DEPTH,
                    "maximum_container_nodes": MAX_ASAR_CONTAINER_NODES,
                    "sample_executed": False,
                }
            for name, node in sorted(tree.items(), reverse=True):
                path = safe_member_name(f"{prefix}/{name}".lstrip("/"), "ASAR")
                if not isinstance(node, dict):
                    continue
                children = node.get("files")
                if isinstance(children, dict):
                    stack.append((path, children, depth + 1))
                    continue
                count += 1
                if count > MAX_MEMBERS:
                    return {
                        "status": "asar_member_limit_blocked",
                        "member_count_lower_bound": count,
                        "maximum_members": MAX_MEMBERS,
                        "sample_executed": False,
                    }
    except (KeyError, RecursionError, TypeError, ValueError):
        return {"status": "not_asar", "sample_executed": False}
    return {
        "status": "accepted",
        "member_count": count,
        "maximum_members": MAX_MEMBERS,
        "sample_executed": False,
    }


def _named_asar_artifacts(
    data: bytes,
    parsed_asar: tuple[dict, list[tuple[str, bytes]]] | None = None,
) -> tuple[dict, list[dict]]:
    """共通parserが返す上限付きblobへ安全なASAR member名を対応付ける。"""
    report, artifacts = parsed_asar if parsed_asar is not None else recover_asar(data)
    by_digest: dict[str, list[tuple[str, bytes]]] = {}
    for kind, blob in artifacts:
        by_digest.setdefault(hashlib.sha256(blob).hexdigest(), []).append((kind, blob))
    named: list[dict] = []
    for item in report.get("inventory", []):
        digest = item.get("sha256")
        candidates = by_digest.get(str(digest), [])
        if not candidates:
            continue
        kind, blob = candidates.pop(0)
        named.append(
            {"name": item["name"], "kind": kind, "blob": blob, "sha256": digest}
        )
    return report, named


def _extract_aes_material(text: str) -> tuple[bytes, bytes] | None:
    """AES key/IVを一意な場合だけ復元する。呼出側は実値を直列化してはならない。"""
    folded = _fold_literal_additions(text)
    matches = re.findall(
        r'module\["exports"\]\s*=\s*\{\s*\["k"\]\s*:\s*"([0-9a-fA-F]{64})"\s*,\s*\["v"\]\s*:\s*"([0-9a-fA-F]{32})"\s*\}',
        folded,
    )
    unique = {(key.lower(), iv.lower()) for key, iv in matches}
    if len(unique) != 1:
        return None
    key, iv = unique.pop()
    return bytes.fromhex(key), bytes.fromhex(iv)


def _decrypt_terminal_pe(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """観測済みAES-256-CBC/PKCS7変換を厳格な上限内で適用する。"""
    if not 16 <= len(ciphertext) <= MAX_CIPHERTEXT or len(ciphertext) % 16:
        raise ValueError("ciphertext size is invalid")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    if not 1 <= len(plaintext) <= MAX_TERMINAL_PE:
        raise ValueError("terminal PE exceeds bounds")
    return plaintext


def _bounded_entropy(data: bytes) -> float:
    """事前に上限確認済みのsectionについてShannonエントロピーを算出する。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    import math

    return round(
        -sum(
            (count / len(data)) * math.log2(count / len(data))
            for count in counts
            if count
        ),
        4,
    )


def characterize_terminal_pe(data: bytes) -> dict:
    """復元した終端PEについて秘密値を含まない構造profileを返す。"""
    if not 1 <= len(data) <= MAX_TERMINAL_PE:
        raise ValueError("terminal PE size is invalid")
    try:
        image = pefile.PE(data=data, fast_load=False)
    except (AttributeError, IndexError, pefile.PEFormatError, ValueError) as exc:
        raise ValueError("terminal payload is not a valid PE") from exc
    sections = []
    expected_end = int(image.OPTIONAL_HEADER.SizeOfHeaders)
    for section in image.sections[:96]:
        start, size = int(section.PointerToRawData), int(section.SizeOfRawData)
        if start < 0 or size < 0 or start + size > len(data):
            raise ValueError("terminal PE section exceeds file bounds")
        expected_end = max(expected_end, start + size)
        name = bytes(section.Name).split(b"\0", 1)[0].decode("ascii", errors="replace")
        sections.append(
            {
                "name": name,
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": size,
                "entropy": _bounded_entropy(data[start : start + size]),
                "characteristics": f"0x{int(section.Characteristics):08x}",
            }
        )
    imports = []
    import_descriptors = getattr(image, "DIRECTORY_ENTRY_IMPORT", [])
    import_symbol_truncated = False
    for descriptor in import_descriptors[:MAX_PE_IMPORT_DESCRIPTORS]:
        dll = bytes(getattr(descriptor, "dll", b"")).decode("ascii", errors="replace")[
            :260
        ]
        symbols = []
        descriptor_imports = getattr(descriptor, "imports", [])
        if len(descriptor_imports) > MAX_PE_IMPORT_SYMBOLS_PER_DLL:
            import_symbol_truncated = True
        for symbol in descriptor_imports[:MAX_PE_IMPORT_SYMBOLS_PER_DLL]:
            name = getattr(symbol, "name", None)
            symbols.append(
                bytes(name).decode("ascii", errors="replace")[:260]
                if name
                else f"ordinal:{int(symbol.ordinal)}"
            )
        imports.append({"dll": dll, "symbols": symbols})
    string_scan = data[:MAX_PE_STRING_SCAN]

    def bounded_strings(pattern: bytes) -> tuple[list[bytes], bool]:
        matches = []
        iterator = re.finditer(pattern, string_scan)
        for match in iterator:
            if len(matches) == MAX_PE_STRINGS_PER_ENCODING:
                return matches, True
            matches.append(match.group())
        return matches, False

    ascii_strings, ascii_truncated = bounded_strings(rb"[ -~]{6,512}")
    wide_strings, wide_truncated = bounded_strings(rb"(?:[ -~]\x00){6,256}")
    section_names = [
        section["name"].encode("ascii", errors="ignore") for section in sections
    ]
    scan = b"\n".join(
        ascii_strings
        + [item.replace(b"\x00", b"") for item in wide_strings]
        + section_names
    ).lower()
    protector_markers = [
        marker
        for marker in ("themida", "winlicense", "vmprotect", "upx")
        if marker.encode("ascii") in scan
    ]
    directories = getattr(image.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
    directory_count = int(getattr(image.OPTIONAL_HEADER, "NumberOfRvaAndSizes", 0) or 0)
    required_directory_indexes = (
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
    )
    if (
        directory_count < max(required_directory_indexes) + 1
        or len(directories) < max(required_directory_indexes) + 1
    ):
        raise ValueError("terminal PE data directory table is truncated")

    def directory(name: str):
        """検証済みdata-directory entryだけを返す。"""
        index = pefile.DIRECTORY_ENTRY[name]
        if index >= directory_count or index >= len(directories):
            raise ValueError("terminal PE data directory table is truncated")
        return directories[index]

    high_entropy_executable_sections = [
        section["name"]
        for section in sections
        if int(section["characteristics"], 16) & 0x20000000
        and section["raw_size"]
        and section["entropy"] >= 7.5
    ]
    zero_raw_virtual_sections = [
        section["name"]
        for section in sections
        if section["virtual_size"] and not section["raw_size"]
    ]
    if "themida" in protector_markers:
        protection_assessment = "themida_marker_present"
    elif protector_markers:
        protection_assessment = "named_protector_marker_present"
    elif high_entropy_executable_sections or zero_raw_virtual_sections:
        protection_assessment = "packed_or_virtualized_likely"
    else:
        protection_assessment = "no_structural_marker"
    return {
        "status": "valid_pe",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "machine": f"0x{int(image.FILE_HEADER.Machine):04x}",
        "entry_point_rva": int(image.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": int(image.OPTIONAL_HEADER.ImageBase),
        "section_count": len(sections),
        "sections": sections,
        "imports": imports,
        "import_descriptor_count": len(imports),
        "import_descriptor_total": len(import_descriptors),
        "import_truncated": {
            "descriptors": len(import_descriptors) > MAX_PE_IMPORT_DESCRIPTORS,
            "symbols": import_symbol_truncated,
        },
        "import_limits": {
            "maximum_descriptors": MAX_PE_IMPORT_DESCRIPTORS,
            "maximum_symbols_per_descriptor": MAX_PE_IMPORT_SYMBOLS_PER_DLL,
        },
        "tls_present": bool(directory("IMAGE_DIRECTORY_ENTRY_TLS").VirtualAddress),
        "export_present": bool(
            directory("IMAGE_DIRECTORY_ENTRY_EXPORT").VirtualAddress
        ),
        "overlay_size": max(0, len(data) - expected_end),
        "protector_markers": protector_markers,
        "protection_assessment": protection_assessment,
        "high_entropy_executable_sections": high_entropy_executable_sections,
        "zero_raw_virtual_sections": zero_raw_virtual_sections,
        "printable_ascii_count": len(ascii_strings),
        "printable_utf16le_count": len(wide_strings),
        "string_scan": {
            "bytes_scanned": len(string_scan),
            "input_truncated": len(data) > len(string_scan),
            "maximum_matches_per_encoding": MAX_PE_STRINGS_PER_ENCODING,
            "ascii_matches_truncated": ascii_truncated,
            "utf16le_matches_truncated": wide_truncated,
        },
        "url_scheme_string_count": len(re.findall(rb"https?://", scan, re.IGNORECASE)),
        "executed": False,
    }


def _minimum_resource_gates(text: str) -> tuple[bool, bool]:
    """観測済みの難読化整数式を評価し、RAM/CPU下限2のgateだけを確認する。"""
    ram_confirmed = False
    ram_match = re.search(
        r"(?:const|let|var)\s+(?P<name>_0x[0-9a-f]+)="
        r'[^;]{0,128}\["totalmem"\]\(\)\s*/\s*\('
        r"(?P<a>[^()*]{1,64})\*(?P<b>[^()*]{1,64})\*(?P<c>[^()*]{1,64})\)\s*;"
        r"\s*if\(\s*(?P=name)\s*<\s*(?P<minimum>[^)]{1,64})\)",
        text,
        re.IGNORECASE,
    )
    if ram_match:
        try:
            divisor = (
                _safe_integer(ram_match.group("a"))
                * _safe_integer(ram_match.group("b"))
                * _safe_integer(ram_match.group("c"))
            )
            minimum = _safe_integer(ram_match.group("minimum"))
            ram_confirmed = divisor == 1024**3 and minimum == 2
        except (SyntaxError, ValueError, ZeroDivisionError):
            ram_confirmed = False

    cpu_confirmed = False
    cpu_match = re.search(
        r"(?:const|let|var)\s+(?P<name>_0x[0-9a-f]+)="
        r'[^;]{0,128}\["cpus"\]\(\)\["length"\]\s*;'
        r"\s*if\(\s*(?P=name)\s*<\s*(?P<minimum>[^)]{1,64})\)",
        text,
        re.IGNORECASE,
    )
    if cpu_match:
        try:
            cpu_confirmed = _safe_integer(cpu_match.group("minimum")) == 2
        except (SyntaxError, ValueError, ZeroDivisionError):
            cpu_confirmed = False
    return ram_confirmed, cpu_confirmed


def _confirmed_minimum_resource_gates(text: str) -> tuple[bool, bool]:
    """RAM/CPUの比較式を含む観測済みgateを上限付きで確認する。"""
    ram_confirmed = False
    ram_match = re.search(
        r"(?:const|let|var)\s+(?P<name>_0x[0-9a-f]+)="
        r'[^;]{0,128}\["totalmem"\]\(\)\s*/\s*(?P<divisor>[^;]{1,256})\s*;'
        r"\s*if\(\s*(?P=name)\s*<\s*(?P<minimum>[^)]{1,64})\)",
        text,
        re.IGNORECASE,
    )
    if ram_match:
        try:
            ram_confirmed = (
                _safe_integer(ram_match.group("divisor")) == 1024**3
                and _safe_integer(ram_match.group("minimum")) == 2
            )
        except (SyntaxError, ValueError, ZeroDivisionError):
            ram_confirmed = False
    _, cpu_confirmed = _minimum_resource_gates(text)
    if not cpu_confirmed:
        cpu_match = re.search(
            r"(?:const|let|var)\s+(?P<name>_0x[0-9a-f]+)="
            r'[^;]{0,128}\["cpus"\]\(\)\["length"\]\s*;'
            r"\s*if\(\s*(?P=name)\s*<\s*(?:\((?P<wrapped>[^()]{1,64})\)|(?P<plain>[^()]{1,64}))\)",
            text,
            re.IGNORECASE,
        )
        if cpu_match:
            threshold = cpu_match.group("wrapped") or cpu_match.group("plain")
            try:
                cpu_confirmed = _safe_integer(threshold) == 2
            except (SyntaxError, ValueError, ZeroDivisionError):
                cpu_confirmed = False
    if not cpu_confirmed:
        cpu_match = re.search(
            r"(?:const|let|var)\s+(?P<name>_0x[0-9a-f]+)="
            r'[^;]{0,128}\["cpus"\]\(\)\["length"\]\s*;'
            r".{0,2048}?\s*if\(\s*(?P=name)\s*<\s*(?P<minimum>[^)]{1,64})\)",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        if cpu_match:
            try:
                cpu_confirmed = _safe_integer(cpu_match.group("minimum")) == 2
            except (SyntaxError, ValueError, ZeroDivisionError):
                cpu_confirmed = False
    return ram_confirmed, cpu_confirmed


def _strip_javascript_comments(text: str) -> str:
    """文字列を保持したままJavaScript commentを空白へ置換する。"""
    output = list(text)
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(text):
        character = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in {'"', "'", "`"}:
            quote = character
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = len(text)
            output[index:end] = " " * (end - index)
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            for position in range(index, end):
                if output[position] not in "\r\n":
                    output[position] = " "
            index = end
            continue
        index += 1
    return "".join(output)


def _javascript_syntax_mask(text: str, *, preserved_property: str | None = None) -> str:
    """文字列・comment・regex literalを同じ長さの空白へ置換する。"""
    output = list(text)
    index = 0

    def blank(left: int, right: int) -> None:
        for position in range(left, right):
            if output[position] not in "\r\n":
                output[position] = " "

    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = len(text) if end < 0 else end
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            blank(index, end)
            index = end
            continue
        character = text[index]
        if character in {'"', "'", "`"}:
            quote = character
            end = index + 1
            escaped = False
            while end < len(text):
                current = text[end]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    end += 1
                    break
                end += 1
            content = text[index + 1 : max(index + 1, end - 1)]
            left = index - 1
            while left >= 0 and text[left].isspace():
                left -= 1
            right = end
            while right < len(text) and text[right].isspace():
                right += 1
            preserve = (
                quote in {'"', "'"}
                and content == preserved_property
                and left >= 0
                and text[left] == "["
                and right < len(text)
                and text[right] == "]"
            )
            if not preserve:
                blank(index, end)
            index = end
            continue
        if character == "/":
            previous = index - 1
            while previous >= 0 and text[previous].isspace():
                previous -= 1
            prefix = text[max(0, previous - 6) : previous + 1]
            regex_context = previous < 0 or text[previous] in "=(:,[!&|?{;"
            regex_context = regex_context or prefix.endswith("return")
            if regex_context:
                end = index + 1
                escaped = False
                in_class = False
                while end < len(text):
                    current = text[end]
                    if escaped:
                        escaped = False
                    elif current == "\\":
                        escaped = True
                    elif current == "[":
                        in_class = True
                    elif current == "]":
                        in_class = False
                    elif current == "/" and not in_class:
                        end += 1
                        while end < len(text) and text[end].isalpha():
                            end += 1
                        break
                    elif current in "\r\n":
                        break
                    end += 1
                blank(index, end)
                index = end
                continue
        index += 1
    return "".join(output)


def _javascript_function_spans(text: str) -> list[tuple[int, int]]:
    """call相関に使う上限付きJavaScript function spanを抽出する。"""
    syntax = _javascript_syntax_mask(text)
    spans: list[tuple[int, int]] = []
    patterns = (
        re.compile(
            r"(?:async\s+)?function(?:\s+[A-Za-z_$][\w$]*)?\s*\([^)]{0,512}\)\s*\{"
        ),
        re.compile(r"(?:\([^)]{0,512}\)|[A-Za-z_$][\w$]*)\s*=>\s*\{"),
    )
    for pattern in patterns:
        for match in pattern.finditer(syntax):
            opening = syntax.find("{", match.start(), match.end())
            try:
                closing = _matching_delimiter(syntax, opening, "{", "}")
            except ValueError:
                continue
            spans.append((match.start(), closing + 1))
            if len(spans) >= 4096:
                return spans
    return spans


def _call_sites(text: str, name: str) -> list[tuple[int, int, str]]:
    """直接またはbracket property形式のcall引数を上限付きで返す。"""
    syntax = _javascript_syntax_mask(text, preserved_property=name)
    pattern = re.compile(
        rf"(?:\[\s*['\"]{re.escape(name)}['\"]\s*\]|(?<![\w$]){re.escape(name)})\s*\("
    )
    calls: list[tuple[int, int, str]] = []
    for match in pattern.finditer(syntax):
        opening = syntax.rfind("(", match.start(), match.end())
        try:
            closing = _matching_delimiter(syntax, opening, "(", ")")
        except ValueError:
            continue
        if closing - opening > 16_384:
            continue
        calls.append((match.start(), closing + 1, text[opening + 1 : closing]))
        if len(calls) >= 1024:
            break
    return calls


def _call_scope(
    text: str, spans: list[tuple[int, int]], start: int, end: int
) -> tuple[str, int]:
    """callを含む最小functionとcallのscope内offsetを返す。"""
    containing = [span for span in spans if span[0] <= start and end <= span[1]]
    if containing:
        left, right = min(containing, key=lambda span: span[1] - span[0])
        return text[left:right], start - left
    left, right = max(0, start - 4096), min(len(text), end + 4096)
    fragment = text[left:right]
    # global callの近傍へ別functionのdead markerを取り込まない。
    for function_start, function_end in spans:
        overlap_left, overlap_right = (
            max(left, function_start),
            min(right, function_end),
        )
        if overlap_left < overlap_right:
            local_left, local_right = overlap_left - left, overlap_right - left
            fragment = (
                fragment[:local_left]
                + " " * (local_right - local_left)
                + fragment[local_right:]
            )
    return fragment, start - left


def _top_level_arguments(arguments: str) -> list[str]:
    """文字列とcontainerを考慮してcallの最上位引数だけを分割する。"""
    output: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    depth = 0
    for index, character in enumerate(arguments):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}" and depth:
            depth -= 1
        elif character == "," and depth == 0:
            output.append(arguments[start:index].strip())
            start = index + 1
    output.append(arguments[start:].strip())
    return output[:16]


def _variable_initializer(scope: str, name: str, before: int) -> str | None:
    """同一function内でcallより前の直近initializerを上限付きで返す。"""
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
        return None
    matches = list(
        re.finditer(
            rf"(?:(?:const|let|var)\s+)?{re.escape(name)}\s*=",
            scope[:before],
        )
    )
    if not matches:
        return None
    start = matches[-1].end()
    quote: str | None = None
    escaped = False
    depth = 0
    for end in range(start, min(before, start + 8192)):
        character = scope[end]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'", "`"}:
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}" and depth:
            depth -= 1
        elif character == ";" and depth == 0:
            return scope[start:end].strip()
    return None


def _resolve_expression_chain(
    scope: str, before: int, expression: str, *, depth: int = 3
) -> str:
    """identifier initializerだけを有限段辿り、call引数とのdataflowを束縛する。"""
    resolved = [expression]
    frontier = re.findall(r"\b[A-Za-z_$][\w$]*\b", expression)
    visited: set[str] = set()
    for _ in range(depth):
        following: list[str] = []
        for name in frontier[:64]:
            if name in visited:
                continue
            visited.add(name)
            initializer = _variable_initializer(scope, name, before)
            if initializer is None:
                continue
            resolved.append(initializer)
            following.extend(re.findall(r"\b[A-Za-z_$][\w$]*\b", initializer))
        frontier = following
        if not frontier:
            break
    return "\n".join(resolved)


def _option_expression(arguments: str, name: str) -> str | None:
    """明示option objectから単純な値式を抽出する。"""
    match = re.search(
        rf"(?:\[\s*['\"]{re.escape(name)}['\"]\s*\]|['\"]?{re.escape(name)}['\"]?)"
        r"\s*:\s*(?P<value>[A-Za-z_$][\w$]*|true|false|['\"][^'\"]{0,260}['\"])",
        arguments,
    )
    return match.group("value") if match else None


def _timeout_values(text: str) -> set[int]:
    """同一call/scopeにあるtimeout整数式だけを安全に評価する。"""
    values: set[int] = set()
    for expression in re.findall(
        r"(?:\[\s*['\"]timeout['\"]\s*\]|\btimeout)\s*:\s*([^,}]{1,128})",
        text,
    ):
        try:
            values.add(_safe_integer(expression))
        except (SyntaxError, ValueError, ZeroDivisionError):
            continue
    return values


def _random_byte_lengths(text: str) -> set[int]:
    """同一functionにあるrandomBytes整数式だけを安全に評価する。"""
    values: set[int] = set()
    for expression in re.findall(
        r"(?:\[\s*['\"]randomBytes['\"]\s*\]|\brandomBytes)\s*\(([^)]{1,128})\)",
        text,
    ):
        try:
            values.add(_safe_integer(expression))
        except (SyntaxError, ValueError, ZeroDivisionError):
            continue
    return values


def _has_boolean_option(arguments: str, name: str, value: bool) -> bool:
    """call引数中の明示boolean optionを確認する。"""
    literal = "true" if value else "false"
    return bool(
        re.search(
            rf"(?:\[\s*['\"]{re.escape(name)}['\"]\s*\]|['\"]?{re.escape(name)}['\"]?)\s*:\s*{literal}\b",
            arguments,
        )
    )


def _boolean_option_is(arguments: str, name: str, value: bool) -> bool:
    """難読化された定数booleanを含む明示option値を安全に比較する。"""
    match = re.search(
        rf"(?:\[\s*['\"]{re.escape(name)}['\"]\s*\]|['\"]?{re.escape(name)}['\"]?)"
        r"\s*:\s*(?P<value>true|false|!!\[\]|!\[\]|!0|!!0)",
        arguments,
    )
    if not match:
        return False
    truthy = {"true", "!![]", "!0"}
    return (match.group("value") in truthy) is value


def _behavior_profile(decoded_scripts: list[str]) -> dict:
    """復号sourceで同一callへ相関できる挙動だけを記述する。"""
    combined = "\n".join(
        _strip_javascript_comments(_fold_literal_additions(item))
        for item in decoded_scripts
    )
    function_spans = _javascript_function_spans(combined)
    logger_match = re.search(
        r'(?:const|let|var)\s+(?P<name>IP_LOGGER_URL)\s*=\s*"(?P<url>[^"]{1,512})"',
        combined,
    )
    logger = logger_match.group("url") if logger_match else ""
    logger_status = "absent"
    if logger.startswith(("http://", "https://")):
        logger_status = "enabled_literal"
    elif logger:
        logger_status = "placeholder_rejected_by_scheme_guard"
    logger_branch_confirmed = False
    for start, end, arguments in _call_sites(combined, "spawnSync"):
        scope, offset = _call_scope(combined, function_spans, start, end)
        call_arguments = _top_level_arguments(arguments)
        if len(call_arguments) < 3:
            continue
        executable = _resolve_expression_chain(
            scope, offset, call_arguments[0], depth=2
        )
        curl_arguments = _resolve_expression_chain(
            scope, offset, call_arguments[1], depth=2
        )
        # logger定数はmodule scope、引数配列はfunction scopeにあるため、
        # callの第2引数から辿れる識別子だけをmodule scopeでも有限段解決する。
        curl_arguments += "\n" + _resolve_expression_chain(
            combined, start, call_arguments[1], depth=4
        )
        if (
            logger_match
            and logger in curl_arguments
            and all(
                literal in executable + "\n" + curl_arguments
                for literal in (
                    "curl.exe",
                    '"-s"',
                    '"-L"',
                    '"-o"',
                    '"NUL"',
                    '"-A"',
                    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
                    '"-m"',
                    '"10"',
                )
            )
            and _boolean_option_is(arguments, "windowsHide", True)
            and not _boolean_option_is(arguments, "shell", True)
            and 15000 in _timeout_values(arguments)
        ):
            logger_branch_confirmed = True
            break

    defender_confirmed = False
    for start, end, arguments in _call_sites(combined, "execSync"):
        scope, offset = _call_scope(combined, function_spans, start, end)
        call_arguments = _top_level_arguments(arguments)
        if len(call_arguments) < 2:
            continue
        command = _resolve_expression_chain(scope, offset, call_arguments[0], depth=3)
        if (
            all(
                marker in command
                for marker in (
                    "Add-MpPreference",
                    "-ExclusionPath",
                    "-ExclusionProcess",
                    "-ExecutionPolicy Bypass",
                    "-WindowStyle Hidden",
                )
            )
            and _boolean_option_is(arguments, "windowsHide", True)
            and 30000 in _timeout_values(arguments)
        ):
            defender_confirmed = True
            break

    terminal_confirmed = False
    for start, end, arguments in _call_sites(combined, "spawn"):
        scope, offset = _call_scope(combined, function_spans, start, end)
        call_arguments = _top_level_arguments(arguments)
        if len(call_arguments) < 3:
            continue
        executable = _resolve_expression_chain(
            scope, offset, call_arguments[0], depth=3
        )
        cwd_expression = _option_expression(arguments, "cwd")
        cwd_chain = (
            _resolve_expression_chain(scope, offset, cwd_expression, depth=3)
            if cwd_expression
            else ""
        )
        assignment = re.search(
            r"(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*$",
            scope[max(0, offset - 256) : offset],
        )
        child_name = assignment.group("name") if assignment else ""
        returned_child_unref = bool(
            child_name
            and re.search(
                rf"\b{re.escape(child_name)}(?:\s*\.\s*unref|\s*\[\s*['\"]unref['\"]\s*\])\s*\(",
                scope[offset + (end - start) :],
            )
        )
        if (
            6 in _random_byte_lengths(executable)
            and 8 in _random_byte_lengths(cwd_chain)
            and '"hex"' in executable + cwd_chain
            and '".exe"' in executable
            and _boolean_option_is(arguments, "detached", True)
            and _boolean_option_is(arguments, "windowsHide", True)
            and bool(
                re.search(
                    r"(?:\[\s*['\"]stdio['\"]\s*\]|['\"]?stdio['\"]?)\s*:\s*['\"]ignore['\"]",
                    arguments,
                )
            )
            and bool(
                re.search(
                    r"(?:\[\s*['\"]cwd['\"]\s*\]|['\"]?cwd['\"]?)\s*:",
                    arguments,
                )
            )
            and returned_child_unref
        ):
            terminal_confirmed = True
            break
    ram_gate_confirmed, cpu_gate_confirmed = _confirmed_minimum_resource_gates(combined)
    return {
        "environment_checks": {
            "minimum_ram_gib_2": ram_gate_confirmed,
            "minimum_cpu_threads_2": cpu_gate_confirmed,
            "registry_product_type": "ProductType" in combined,
            "virtualization_registry_keys": "Virtual Machine" in combined
            and "VMware Tools" in combined,
            "bios_cloud_markers": "SystemManufacturer" in combined
            and "BIOSVendor" in combined,
            "gpu_driverdesc_query": "DriverDesc" in combined,
        },
        "logger": {
            "status": logger_status,
            "url": _defang_url(logger) if logger_status == "enabled_literal" else None,
            "curl_argument_template": [
                "-s",
                "-L",
                "-o",
                "NUL",
                "-A",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "-m",
                "10",
                "<logger-url>",
            ]
            if logger_branch_confirmed
            else [],
            "curl_max_time_seconds": 10 if logger_branch_confirmed else None,
            "spawn_sync_timeout_ms": 15000 if logger_branch_confirmed else None,
            "windows_hide": True if logger_branch_confirmed else None,
            "shell": False if logger_branch_confirmed else None,
            "branch_confirmed": logger_branch_confirmed,
        },
        "defender_exclusion": {
            "status": "confirmed"
            if defender_confirmed
            else ("marker_incomplete" if "Add-MpPreference" in combined else "absent"),
            "present": defender_confirmed,
            "command_template": r'''powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath '<tempdir>' -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionPath '<tempdir>\<12hex>.exe' -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess '<12hex>.exe' -ErrorAction SilentlyContinue"'''
            if defender_confirmed
            else None,
            "timeout_ms": 30000 if defender_confirmed else None,
            "windows_hide": True if defender_confirmed else None,
            "launch_method": "execSync_via_shell" if defender_confirmed else None,
        },
        "terminal_process": {
            "status": "confirmed" if terminal_confirmed else "absent_or_incomplete",
            "executable_template": r"<tempdir>\<12hex>.exe"
            if terminal_confirmed
            else None,
            "command_line_template": r'"<tempdir>\<12hex>.exe"'
            if terminal_confirmed
            else None,
            "arguments": [] if terminal_confirmed else None,
            "cwd": "<tempdir>" if terminal_confirmed else None,
            "detached": True if terminal_confirmed else None,
            "stdio": "ignore" if terminal_confirmed else None,
            "windows_hide": True if terminal_confirmed else None,
            "unref": True if terminal_confirmed else None,
        },
        "sample_executed": False,
    }


def _validate_recovery_integrity(
    asar_report: dict,
    aes_material_report: dict,
    terminal_profile: dict,
    terminal: bytes,
) -> None:
    """公開reportのdigest形式と復元artifactとの対応が崩れた場合に停止する。"""
    actual_terminal = hashlib.sha256(terminal).hexdigest()
    digests = {
        "terminal_pe.sha256": terminal_profile.get("sha256"),
        "aes_material.key_sha256": aes_material_report.get("key_sha256"),
        "aes_material.iv_sha256": aes_material_report.get("iv_sha256"),
    }
    for index, item in enumerate(asar_report.get("inventory", [])):
        if "sha256" in item:
            digests[f"asar.inventory[{index}].sha256"] = item.get("sha256")
    for label, digest in digests.items():
        if not isinstance(digest, str) or not _SHA256_PATTERN.fullmatch(digest):
            raise ValueError(f"invalid SHA-256 digest: {label}")
    if terminal_profile["sha256"] != actual_terminal:
        raise ValueError("terminal PE digest does not match recovered artifact")


def recover_payload_from_asar(
    data: bytes,
    *,
    parsed_asar: tuple[dict, list[tuple[str, bytes]]] | None = None,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """ASARからAESで包まれた終端PE 1件を静的解析だけで復元する。"""
    preflight = electron_asar_preflight(data)
    if preflight["status"] != "accepted":
        return preflight, []
    if not is_asar(data):
        return {"status": "not_asar", "sample_executed": False}, []
    asar_report, named = _named_asar_artifacts(data, parsed_asar)
    script_candidates = [
        item
        for item in named
        if PurePosixPath(item["name"]).suffix.lower() in {".js", ".cjs", ".mjs"}
    ]
    script_bytes = sum(len(item["blob"]) for item in script_candidates)
    if (
        len(script_candidates) > MAX_ELECTRON_SCRIPTS
        or script_bytes > MAX_ELECTRON_SCRIPT_BYTES
    ):
        return {
            "status": "script_budget_blocked",
            "asar": asar_report,
            "script_candidate_count": len(script_candidates),
            "script_candidate_bytes": script_bytes,
            "maximum_scripts": MAX_ELECTRON_SCRIPTS,
            "maximum_script_bytes": MAX_ELECTRON_SCRIPT_BYTES,
            "sample_executed": False,
        }, []
    decoded_reports, decoded_texts = [], []
    for item in script_candidates:
        decode_report, transformed = deobfuscate_generated_alphabet_rc4(item["blob"])
        decoded_reports.append({"name": item["name"], **decode_report})
        if transformed is not None:
            decoded_texts.append(decode_script_text(transformed))
    materials = [
        value
        for text in decoded_texts
        if (value := _extract_aes_material(text)) is not None
    ]
    unique_materials = {(key, iv) for key, iv in materials}
    main_scripts = [
        text
        for text in decoded_texts
        if "createDecipheriv" in text and "aes-256-cbc" in _fold_literal_additions(text)
    ]
    if len(unique_materials) != 1 or len(main_scripts) != 1:
        return {
            "status": "payload_recipe_not_unique",
            "asar": asar_report,
            "decoded_scripts": decoded_reports,
            "key_config_count": len(unique_materials),
            "main_script_count": len(main_scripts),
            "sample_executed": False,
        }, []
    main = _fold_literal_additions(main_scripts[0])
    dat_names = set(re.findall(r'["\']([^"\']{1,260}\.dat)["\']', main, re.IGNORECASE))
    ciphertexts = [
        item["blob"]
        for item in named
        if PurePosixPath(item["name"]).name
        in {PurePosixPath(value).name for value in dat_names}
    ]
    if len(ciphertexts) != 1:
        return {
            "status": "ciphertext_not_unique",
            "asar": asar_report,
            "decoded_scripts": decoded_reports,
            "ciphertext_candidate_count": len(ciphertexts),
            "sample_executed": False,
        }, []
    key, iv = unique_materials.pop()
    aes_material_report = {
        "algorithm": "AES-256-CBC",
        "padding": "PKCS7",
        "key_length": len(key),
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "iv_length": len(iv),
        "iv_sha256": hashlib.sha256(iv).hexdigest(),
        "values_published": False,
    }
    try:
        terminal = _decrypt_terminal_pe(ciphertexts[0], key, iv)
        profile = characterize_terminal_pe(terminal)
        _validate_recovery_integrity(
            asar_report, aes_material_report, profile, terminal
        )
    except (ValueError, TypeError) as exc:
        return {
            "status": "terminal_validation_failed",
            "error": type(exc).__name__,
            "asar": asar_report,
            "decoded_scripts": decoded_reports,
            "sample_executed": False,
        }, []
    return {
        "status": "terminal_pe_recovered",
        "asar": asar_report,
        "decoded_scripts": decoded_reports,
        "behavior": _behavior_profile(decoded_texts),
        "terminal_pe": profile,
        "aes_material": aes_material_report,
        "sample_executed": False,
    }, [("electron-terminal-pe", terminal)]


def safe_archive_member(name: str) -> str:
    """未信頼7-Zip member path 1件を正規化し検証する。"""
    return safe_member_name(name, "archive")


def select_nested_7z_members(names: list[str]) -> list[str]:
    """NSIS一覧から上限付きの入れ子7z候補を返す。"""
    candidates = []
    for name in names[:MAX_MEMBERS]:
        normalized = safe_archive_member(name)
        if normalized.lower().endswith(".7z"):
            candidates.append(name)
    return candidates[:8]


def select_asar_members(names: list[str]) -> list[str]:
    """標準pathを優先し、上限付きapp.asar候補を返す。"""
    candidates = []
    for name in names[:MAX_MEMBERS]:
        normalized = safe_archive_member(name)
        if normalized.lower().endswith(".asar"):
            priority = 0 if normalized.lower().endswith("resources/app.asar") else 1
            candidates.append((priority, normalized.lower(), name))
    return [item[2] for item in sorted(candidates)[:8]]


def list_archive(path: Path, executable: Path, timeout: float = 60.0) -> dict:
    """7-Zipでarchive 1件を列挙し、上限付きtype/member metadataを返す。"""
    completed = _run_static_tool_process(
        [str(executable), "l", "-slt", "--", str(path)],
        cwd=path.parent,
        timeout=timeout,
        max_temp_entries=MAX_STATIC_TOOL_TEMP_ENTRIES,
        max_temp_bytes=MAX_STATIC_TOOL_TEMP_BYTES,
    )
    names, types = [], []
    for line in completed.stdout.splitlines():
        if line.startswith("Path = "):
            value = line[7:]
            if value != str(path):
                names.append(value)
        elif line.startswith("Type = "):
            types.append(line[7:])
    return {
        "status": "listed" if completed.returncode == 0 else "unsupported",
        "exit_code": completed.returncode,
        "types": sorted(set(types)),
        "members": names[:MAX_MEMBERS],
        "total_members": len(names),
    }


def extract_member(
    path: Path, member: str, output: Path, executable: Path, timeout: float = 180.0
) -> Path:
    """検証済みarchive member 1件を抽出し、一意なlocal pathを返す。"""
    normalized = safe_archive_member(member)
    output.mkdir(parents=True, exist_ok=True)
    working_root = Path(
        os.path.commonpath((str(path.resolve()), str(output.resolve())))
    )
    completed = _run_static_tool_process(
        [str(executable), "x", "-y", "-bd", "-bb0", f"-o{output}", str(path), member],
        cwd=working_root,
        timeout=timeout,
        max_temp_entries=MAX_STATIC_TOOL_TEMP_ENTRIES,
        max_temp_bytes=MAX_STATIC_TOOL_TEMP_BYTES,
    )
    if completed.returncode != 0:
        raise ValueError(f"7-Zip extraction failed: {completed.returncode}")
    expected = output.joinpath(*PurePosixPath(normalized).parts)
    _read_static_tool_output(expected, root=output, maximum_size=MAX_ARCHIVE)
    return expected


def recover_electron_asars(
    data: bytes, executable: Path
) -> tuple[dict, list[tuple[str, bytes]]]:
    """app bundle全体を展開せず、入れ子Electron ASARを静的復元する。"""
    if not executable.is_file():
        return {"status": "unavailable", "sample_executed": False}, []
    if not 0 < len(data) <= MAX_ARCHIVE:
        return {"status": "outer_size_blocked", "size": len(data)}, []
    reports, artifacts = [], []
    with tempfile.TemporaryDirectory(prefix="asa-electron-nsis-") as directory:
        root = Path(directory)
        outer = root / "outer.bin"
        outer.write_bytes(data)
        outer_listing = list_archive(outer, executable)
        if "Nsis" not in outer_listing.get("types", []) and "nsis" not in {
            value.lower() for value in outer_listing.get("types", [])
        }:
            return {**outer_listing, "status": "not_nsis"}, []
        for index, nested_name in enumerate(
            select_nested_7z_members(outer_listing["members"])
        ):
            item = {"nested_member": safe_archive_member(nested_name)}
            try:
                nested = extract_member(
                    outer, nested_name, root / f"outer-{index}", executable
                )
                if not 0 < nested.stat().st_size <= MAX_ARCHIVE:
                    item.update(
                        status="nested_size_blocked", size=nested.stat().st_size
                    )
                    reports.append(item)
                    continue
                listing = list_archive(nested, executable)
                item["nested_listing"] = listing
                for asar_index, asar_name in enumerate(
                    select_asar_members(listing["members"])
                ):
                    path = extract_member(
                        nested,
                        asar_name,
                        root / f"asar-{index}-{asar_index}",
                        executable,
                    )
                    if not 0 < path.stat().st_size <= MAX_ASAR:
                        continue
                    blob = _read_static_tool_output(
                        path, root=root, maximum_size=MAX_ASAR
                    )
                    if not is_asar(blob):
                        continue
                    digest = hashlib.sha256(blob).hexdigest()
                    artifacts.append(("electron-app-asar", blob))
                    payload_report, payload_artifacts = recover_payload_from_asar(blob)
                    artifacts.extend(payload_artifacts)
                    item.setdefault("asars", []).append(
                        {
                            "name": safe_archive_member(asar_name),
                            "size": len(blob),
                            "sha256": digest,
                            "payload_chain": payload_report,
                        }
                    )
                item["status"] = "asar_recovered" if item.get("asars") else "no_asar"
            except (OSError, StaticToolExecutionError, ValueError) as exc:
                item.update(status="recovery_failed", error=type(exc).__name__)
            reports.append(item)
    seen, deduplicated = set(), []
    for kind, blob in artifacts:
        digest = hashlib.sha256(blob).hexdigest()
        if digest not in seen:
            seen.add(digest)
            deduplicated.append((kind, blob))
    terminal_recovered = any(kind == "electron-terminal-pe" for kind, _ in deduplicated)
    return {
        "status": "terminal_pe_recovered"
        if terminal_recovered
        else ("asar_recovered" if deduplicated else "no_asar_recovered"),
        "outer_listing": outer_listing,
        "nested": reports,
        "sample_executed": False,
    }, deduplicated
