"""Environment分割型JScriptローダーからmanaged assemblyを静的復元する。

対象は、区切り文字を各Base64文字へ挿入し、復元後の文字列を
``HKCU\\Environment``へ分割保存してPowerShellの``Assembly.Load``へ渡す型である。
JavaScript、PowerShell、復元したassemblyはいずれも実行しない。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re

import pefile

from unpackers.javascript_reverse_base64 import _decode_javascript_string
from unpackers.managed_win32_rmp_loader import recover_win32_rmp_loader_config

MAX_SCRIPT_SIZE = 16 * 1024 * 1024
MAX_TEXT_SIZE = 8 * 1024 * 1024
MAX_LITERAL_SEGMENTS = 256
MAX_JOINED_CHARACTERS = 32 * 1024 * 1024
MAX_DECODED_SIZE = 64 * 1024 * 1024
MAX_ENVIRONMENT_CHUNKS = 512
MIN_DECODED_SIZE = 1024
MIN_SEPARATOR_OCCURRENCES = 256

_IDENTIFIER = r"[A-Za-z_$][\w$]*"
_BASE64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_utf16le(data: bytes) -> tuple[str | None, str]:
    if len(data) > MAX_SCRIPT_SIZE:
        return None, "size_blocked"
    if not data.startswith(b"\xff\xfe"):
        return None, "utf16le_bom_not_found"
    if len(data) % 2:
        return None, "utf16le_length_invalid"
    try:
        text = data[2:].decode("utf-16le", errors="surrogatepass")
    except UnicodeDecodeError:
        return None, "utf16le_decode_failed"
    if len(text) > MAX_TEXT_SIZE:
        return None, "text_size_blocked"
    return text, "decoded"


def _recompose_surrogates(value: str) -> str:
    """別々の文字列literal境界へ分割されたUTF-16 surrogateを再構成する。"""
    return value.encode("utf-16le", errors="surrogatepass").decode("utf-16le")


def _split_recipes(lines: list[str]) -> list[tuple[str, str]]:
    pattern = re.compile(
        rf"^\s*(?P<name>{_IDENTIFIER})\s*=\s*(?P=name)\.split\("
        r'"(?P<separator>(?:\\.|[^"\\]){1,256})"\)\.join\(""\);\s*$'
    )
    recipes: list[tuple[str, str]] = []
    for line in lines:
        match = pattern.match(line)
        if match is None:
            continue
        try:
            separator = _decode_javascript_string(match.group("separator"))
        except (UnicodeError, ValueError):
            continue
        if not separator or len(separator) > 64:
            continue
        recipes.append((match.group("name"), separator))
    return recipes


def _literal_fragments(lines: list[str], name: str) -> list[str] | None:
    pattern = re.compile(
        rf"^\s*(?:var\s+)?{re.escape(name)}\s*(?P<operator>\+?=)\s*"
        r'"(?P<literal>(?:\\.|[^"\\])*)";\s*$'
    )
    fragments: list[str] = []
    initialized = False
    for line in lines:
        match = pattern.match(line)
        if match is None:
            continue
        operator = match.group("operator")
        if operator == "=":
            if initialized:
                return None
            initialized = True
        elif not initialized:
            return None
        if len(fragments) >= MAX_LITERAL_SEGMENTS:
            return None
        try:
            fragment = _decode_javascript_string(match.group("literal"))
        except (UnicodeError, ValueError):
            return None
        fragments.append(fragment)
        if sum(map(len, fragments)) > MAX_JOINED_CHARACTERS:
            return None
    return fragments if initialized and fragments else None


def _valid_pe(data: bytes) -> bool:
    if not data.startswith(b"MZ"):
        return False
    try:
        image = pefile.PE(data=data, fast_load=True)
        clr = image.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        ]
        return (
            1 <= image.FILE_HEADER.NumberOfSections <= 96
            and clr.VirtualAddress > 0
            and clr.Size >= 0x48
        )
    except (AttributeError, ValueError, pefile.PEFormatError):
        return False


def _decode_payload(
    lines: list[str], name: str, separator: str
) -> tuple[dict[str, object], bytes | None]:
    fragments = _literal_fragments(lines, name)
    if fragments is None:
        return {"status": "literal_chain_not_found"}, None
    try:
        joined = _recompose_surrogates("".join(fragments))
    except UnicodeError:
        return {"status": "surrogate_recomposition_failed"}, None
    separator_count = joined.count(separator)
    if separator_count < MIN_SEPARATOR_OCCURRENCES:
        return {"status": "separator_evidence_insufficient"}, None
    compact = joined.replace(separator, "")
    if (
        not compact
        or len(compact) % 4
        or any(value not in _BASE64 for value in compact)
    ):
        return {"status": "base64_shape_invalid"}, None
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error):
        return {"status": "base64_decode_failed"}, None
    if not MIN_DECODED_SIZE <= len(decoded) <= MAX_DECODED_SIZE:
        return {"status": "decoded_size_blocked"}, None
    if base64.b64encode(decoded).decode("ascii") != compact:
        return {"status": "base64_not_canonical"}, None
    if not _valid_pe(decoded):
        return {"status": "decoded_artifact_not_pe"}, None
    return {
        "status": "pe_decoded",
        "literal_segments": len(fragments),
        "separator_code_points": len(separator),
        "separator_occurrences": separator_count,
        "base64_size": len(compact),
        "decoded_size": len(decoded),
        "decoded_sha256": _sha256(decoded),
    }, decoded


def _environment_recipe(
    lines: list[str], payload_name: str, base64_size: int
) -> dict[str, object] | None:
    accumulator_pattern = re.compile(
        rf"^\s*(?P<acc>{_IDENTIFIER})\s*=\s*(?P=acc)\s*\+\s*"
        rf'"\$env:"\s*\+\s*(?P<key>{_IDENTIFIER})\s*\+\s*"\+";\s*$'
    )
    accumulator_matches = [
        match
        for line in lines
        if (match := accumulator_pattern.match(line)) is not None
    ]
    if len(accumulator_matches) != 1:
        return None
    accumulator_match = accumulator_matches[0]
    accumulator = accumulator_match.group("acc")
    key_name = accumulator_match.group("key")
    item_pattern = re.compile(
        rf"^\s*(?P<environment>{_IDENTIFIER})\.Item\(\s*{re.escape(key_name)}\s*\)"
        rf"\s*=\s*{re.escape(payload_name)}\.substr\(\s*"
        rf"(?P<offset>{_IDENTIFIER})\s*,\s*(?P<size_name>{_IDENTIFIER})\s*\);\s*$"
    )
    item_matches = [
        match for line in lines if (match := item_pattern.match(line)) is not None
    ]
    if len(item_matches) != 1:
        return None
    item_match = item_matches[0]
    environment_name = item_match.group("environment")
    offset_name = item_match.group("offset")
    size_name = item_match.group("size_name")
    shell_pattern = re.compile(
        rf"^\s*(?:var\s+)?(?P<shell>{_IDENTIFIER})\s*=\s*new\s+"
        r'ActiveXObject\(\s*"WScript\.Shell"\s*\);\s*$'
    )
    shell_names = {
        match.group("shell")
        for line in lines
        if (match := shell_pattern.match(line)) is not None
    }
    environment_pattern = re.compile(
        rf"^\s*(?:var\s+)?{re.escape(environment_name)}\s*=\s*"
        rf'(?P<shell>{_IDENTIFIER})\.Environment\(\s*"User"\s*\);\s*$'
    )
    environment_shells = {
        match.group("shell")
        for line in lines
        if (match := environment_pattern.match(line)) is not None
    }
    if len(environment_shells) != 1 or not environment_shells <= shell_names:
        return None
    loop_pattern = re.compile(
        rf"^\s*for\s*\(\s*(?:var\s+)?{re.escape(offset_name)}\s*=\s*0\s*;"
        rf"\s*{re.escape(offset_name)}\s*<\s*{re.escape(payload_name)}\.length\s*;"
        rf"\s*{re.escape(offset_name)}\s*\+=\s*{re.escape(size_name)}\s*\)\s*\{{\s*$"
    )
    if sum(bool(loop_pattern.match(line)) for line in lines) != 1:
        return None
    size_pattern = re.compile(
        rf"^\s*(?:var\s+)?{re.escape(size_name)}\s*=\s*(?P<size>\d{{1,8}});\s*$"
    )
    sizes = {
        int(match.group("size"))
        for line in lines
        if (match := size_pattern.match(line)) is not None
    }
    if len(sizes) != 1:
        return None
    chunk_size = sizes.pop()
    if not 1 <= chunk_size <= 1_000_000:
        return None
    chunk_count = math.ceil(base64_size / chunk_size)
    if not 1 <= chunk_count <= MAX_ENVIRONMENT_CHUNKS:
        return None
    return {
        "accumulator": accumulator,
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
        "registry_scope": "HKCU\\Environment",
    }


def _concat_tokens(expression: str) -> list[tuple[str, str]] | None:
    token = re.compile(
        rf'\s*(?:"(?P<literal>(?:\\.|[^"\\])*)"|(?P<name>{_IDENTIFIER}))'
        r"\s*(?P<separator>\+|$)"
    )
    output: list[tuple[str, str]] = []
    offset = 0
    while offset < len(expression):
        match = token.match(expression, offset)
        if match is None or match.end() == offset:
            return None
        if match.group("literal") is not None:
            try:
                value = _decode_javascript_string(match.group("literal"))
            except (UnicodeError, ValueError):
                return None
            output.append(("literal", value))
        else:
            output.append(("identifier", match.group("name")))
        offset = match.end()
    return output or None


def _quoted_arguments(raw: str) -> list[str] | None:
    argument = re.compile(r"\s*'(?P<value>(?:\\.|[^'\\])*)'\s*(?P<separator>,|$)")
    values: list[str] = []
    offset = 0
    while offset < len(raw):
        match = argument.match(raw, offset)
        if match is None or match.end() == offset:
            return None
        try:
            values.append(_decode_javascript_string(match.group("value")))
        except (UnicodeError, ValueError):
            return None
        offset = match.end()
    return values or None


def _argument_metadata(arguments: list[str]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for index, value in enumerate(arguments):
        item: dict[str, object] = {
            "index": index,
            "empty": not value,
            "encoded_size": len(value),
        }
        if value:
            try:
                decoded = base64.b64decode(value, validate=True)
            except (ValueError, binascii.Error):
                item["strict_base64"] = False
            else:
                item.update(
                    {
                        "strict_base64": base64.b64encode(decoded).decode("ascii")
                        == value,
                        "decoded_size": len(decoded),
                        "decoded_sha256": _sha256(decoded),
                    }
                )
        result.append(item)
    return result


def _command_contract(
    lines: list[str],
    recipes: list[tuple[str, str]],
    payload_name: str,
    separator: str,
    environment: dict[str, object],
) -> tuple[dict[str, object], list[str]] | None:
    accumulator = str(environment["accumulator"])
    command_candidates: list[tuple[dict[str, object], list[str]]] = []
    assignment = re.compile(
        rf"^\s*var\s+(?P<name>{_IDENTIFIER})\s*=\s*(?P<expression>.+);\s*$"
    )
    expressions: dict[str, list[str]] = {}
    for line in lines:
        match = assignment.match(line)
        if match is not None:
            expressions.setdefault(match.group("name"), []).append(
                match.group("expression")
            )
    for command_name, command_separator in recipes:
        if command_name == payload_name or command_separator != separator:
            continue
        command_expressions = expressions.get(command_name, [])
        if len(command_expressions) != 1:
            continue
        expression = command_expressions[0]
        tokens = _concat_tokens(expression)
        if tokens is None:
            continue
        identifiers = [value for kind, value in tokens if kind == "identifier"]
        if not identifiers or set(identifiers) != {accumulator}:
            continue
        command_parts: list[str] = []
        try:
            for kind, value in tokens:
                if kind == "identifier":
                    command_parts.append("$env:P1+...+$env:Pn")
                else:
                    command_parts.append(
                        _recompose_surrogates(value).replace(separator, "")
                    )
        except UnicodeError:
            continue
        command = "".join(command_parts)
        lowered = command.lower()
        anchors = (
            "powershell",
            "[system.reflection.assembly]::load(",
            "[convert]::frombase64string(",
        )
        if not all(anchor in lowered for anchor in anchors):
            continue
        process_binding = re.compile(
            rf"^\s*(?:var\s+)?(?P<process>{_IDENTIFIER})\s*=\s*{_IDENTIFIER}"
            r'\.Get\(\s*"Win32_Process"\s*\);\s*$'
        )
        process_names = {
            match.group("process")
            for line in lines
            if (match := process_binding.match(line)) is not None
        }
        create_pattern = re.compile(
            rf"^\s*(?P<process>{_IDENTIFIER})\.Create\(\s*"
            rf"{re.escape(command_name)}\s*,"
        )
        invoked_processes = [
            match.group("process")
            for line in lines
            if (match := create_pattern.match(line)) is not None
            and match.group("process") in process_names
        ]
        if len(invoked_processes) != 1:
            continue
        invocation_pattern = re.compile(
            rf"\]::(?P<method>{_IDENTIFIER})\("
            r"(?P<args>(?:\s*'(?:\\.|[^'\\])*'\s*,)*"
            r"\s*'(?:\\.|[^'\\])*'\s*)\)"
        )
        invocations: list[tuple[str, list[str]]] = []
        for invocation in invocation_pattern.finditer(command):
            arguments = _quoted_arguments(invocation.group("args"))
            if arguments is not None:
                invocations.append((invocation.group("method"), arguments))
        if len(invocations) != 1:
            continue
        method, arguments = invocations[0]
        command_candidates.append(
            (
                {
                    "command_variable": command_name,
                    "static_method": method,
                    "argument_count": len(arguments),
                    "nonempty_argument_count": sum(bool(value) for value in arguments),
                    "arguments": _argument_metadata(arguments),
                    "command_sha256": _sha256(command.encode("utf-8")),
                },
                arguments,
            )
        )
    if len(command_candidates) != 1:
        return None
    return command_candidates[0]


def recover_javascript_env_assembly(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """厳密に一致したJScript loaderからPEを復元し、次段へ渡す。"""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    text, decode_status = _decode_utf16le(data)
    if text is None:
        return {
            "status": decode_status,
            "executed": False,
            "network_contacted": False,
        }, []
    lines = text.splitlines()
    recipes = _split_recipes(lines)
    accepted: list[tuple[dict[str, object], bytes]] = []
    decoded_candidate_count = 0
    for name, separator in recipes:
        payload_report, payload = _decode_payload(lines, name, separator)
        if payload is None:
            continue
        decoded_candidate_count += 1
        environment = _environment_recipe(
            lines, name, int(payload_report["base64_size"])
        )
        if environment is None:
            continue
        command_contract = _command_contract(
            lines, recipes, name, separator, environment
        )
        if command_contract is None:
            continue
        command, arguments = command_contract
        loader_configuration = recover_win32_rmp_loader_config(payload, arguments)
        accepted.append(
            (
                {
                    **payload_report,
                    "payload_variable": name,
                    "environment": environment,
                    "invocation": command,
                    "loader_configuration": loader_configuration,
                },
                payload,
            )
        )
    if len(accepted) != 1:
        status = "ambiguous_candidates" if len(accepted) > 1 else "pattern_not_found"
        return {
            "status": status,
            "split_recipe_count": len(recipes),
            "decoded_pe_candidate_count": decoded_candidate_count,
            "accepted_candidate_count": len(accepted),
            "executed": False,
            "network_contacted": False,
        }, []
    candidate, payload = accepted[0]
    configuration = candidate["loader_configuration"]
    configuration_recovered = (
        isinstance(configuration, dict)
        and configuration.get("status") == "loader_configuration_recovered"
    )
    return {
        "pattern": "unicode_delimited_base64_environment_assembly_load",
        **candidate,
        "status": "managed_assembly_recovered",
        "evidence_boundary": {
            "supports_family_attribution": False,
            "supports_c2_confirmation": False,
            "loader_arguments_decrypted": configuration_recovered,
            "payload_acquisition_url_recovered": configuration_recovered,
        },
        "executed": False,
        "network_contacted": False,
    }, [("javascript-env-assembly-pe", payload)]
