"""PowerShellの定数Base64/XOR呼出しを実行せずに復元する。

対象は、数値配列を固定鍵との減算で文字列化し、その文字列から構成した
Base64/XOR helperを通じて複数のscript断片を ``IEX`` へ渡す、レビュー済みの
限定profileである。PowerShell評価器や一般式評価器は使用しない。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass

PROFILE_NAME = "powershell-cyclic-xor-base64-calls-v1"
_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_ARRAY_RE = re.compile(r"@\(\s*(\d+(?:\s*,\s*\d+)+)\s*\)", re.IGNORECASE)
_FUNCTION_RE = re.compile(rf"\bfunction\s+({_IDENTIFIER})\s*\(", re.IGNORECASE)
_URL_RE = re.compile(r"(?i)^https?://[^\s\"'<>]+$")
_HELPER_PATTERNS = {
    "byte_xor": re.compile(
        rf"^\s*\${_IDENTIFIER}\s*-bxor\s*\(\s*\${_IDENTIFIER}\s*\)\s*$",
        re.IGNORECASE,
    ),
    "invoke_expression": re.compile(r"^\s*iex\s*$", re.IGNORECASE),
    "strict_base64": re.compile(
        rf"^\s*\[convert\]::frombase64string\(\s*\${_IDENTIFIER}\s*\)\s*$",
        re.IGNORECASE,
    ),
    "char_join": re.compile(
        rf"^\s*-join\s+\[char\[\]\]\s*\${_IDENTIFIER}\s*$",
        re.IGNORECASE,
    ),
}
_EXPECTED_HELPER_ROLES = frozenset(_HELPER_PATTERNS)


@dataclass(frozen=True)
class CyclicXorCallLimits:
    """限定profileに対するhard limit。"""

    max_input_bytes: int = 2 * 1024 * 1024
    max_array_candidates: int = 256
    max_array_items: int = 4_096
    max_key_items: int = 64
    max_function_names: int = 64
    max_calls_per_function: int = 256
    max_base64_characters: int = 2 * 1024 * 1024
    max_decoded_bytes: int = 1 * 1024 * 1024
    max_artifacts: int = 128
    max_work_units: int = 64 * 1024 * 1024


DEFAULT_LIMITS = CyclicXorCallLimits()


@dataclass(frozen=True)
class RemotePayloadTransformLimits:
    """取得済みresponseへ静的変換だけを適用する際のhard limit。"""

    max_input_bytes: int = 64 * 1024 * 1024
    max_decoded_bytes: int = 48 * 1024 * 1024
    max_output_bytes: int = 32 * 1024 * 1024


DEFAULT_REMOTE_LIMITS = RemotePayloadTransformLimits()


@dataclass(frozen=True)
class CyclicXorContext:
    """親層で厳格検証した、公開reportとmemory内だけの復号context。"""

    report: dict[str, object]
    key: bytes | None
    function_name: str | None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _base_report(
    data: bytes,
    limits: CyclicXorCallLimits,
    *,
    status: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "profile": PROFILE_NAME,
        "input_size": len(data),
        "input_sha256": _sha256(data),
        "candidate_set_complete": False,
        "candidate_set_truncated": False,
        "candidate_count": 0,
        "limits": asdict(limits),
        "candidates": [],
        "rejections": {},
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "powershell_started": False,
            "general_expression_evaluator_used": False,
            "raw_key_included": False,
            "raw_script_included": False,
        },
        "evidence_boundary": {
            "family_attribution_allowed": False,
            "c2_confirmation_allowed": False,
            "delivery_url_is_c2_confirmation": False,
            "terminal_payload_recovered": False,
        },
    }


def _decode_source(data: bytes) -> tuple[str, str] | None:
    encodings = (
        ("utf-16-le", data[2:]) if data.startswith(b"\xff\xfe") else None,
        ("utf-8-sig", data),
        ("cp1252", data),
    )
    for candidate in encodings:
        if candidate is None:
            continue
        encoding, source = candidate
        try:
            text = source.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\x00" not in text:
            return text, encoding
    return None


def _parse_numbers(value: str, *, maximum: int) -> list[int] | None:
    parts = value.split(",")
    if not 2 <= len(parts) <= maximum:
        return None
    numbers: list[int] = []
    for part in parts:
        try:
            number = int(part.strip(), 10)
        except ValueError:
            return None
        if not 0 <= number <= 0x10FFFF + 0xFF:
            return None
        numbers.append(number)
    return numbers


def _subtract_key(numbers: list[int], key: list[int]) -> str | None:
    output: list[str] = []
    for index, number in enumerate(numbers):
        value = number - key[index % len(key)]
        if value == 0:
            break
        if not 0 <= value <= 0x10FFFF or 0xD800 <= value <= 0xDFFF:
            return None
        output.append(chr(value))
    text = "".join(output)
    if not text or not all(
        character.isprintable() or character in "\r\n\t" for character in text
    ):
        return None
    return text


def _helper_role(value: str) -> str | None:
    """変数名を固定せず、レビュー済みhelper式の構文だけを分類する。"""

    matches = [
        role for role, pattern in _HELPER_PATTERNS.items() if pattern.fullmatch(value)
    ]
    return matches[0] if len(matches) == 1 else None


def _xor_decode(
    encoded: str, key: list[int], limits: CyclicXorCallLimits
) -> bytes | None:
    if not encoded or len(encoded) > limits.max_base64_characters or len(encoded) % 4:
        return None
    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not ciphertext or len(ciphertext) > limits.max_decoded_bytes:
        return None
    return bytes(
        value ^ key[index % len(key)] for index, value in enumerate(ciphertext)
    )


def _printable_text(value: bytes) -> str | None:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or "\x00" in text:
        return None
    printable = sum(
        character.isprintable() or character in "\r\n\t" for character in text
    )
    if printable / len(text) < 0.98:
        return None
    return text


def _looks_like_script_fragment(text: str) -> bool:
    lowered = text.casefold()
    anchors = {
        "variable": "$" in text,
        "assignment": "=" in text,
        "powershell_type": "[" in text and "]" in text,
        "member": "::" in text or "." in text,
        "statement": ";" in text or "\n" in text,
        "keyword": any(
            keyword in lowered
            for keyword in ("new-object", "invoke-", "function", "if(", "if (")
        ),
    }
    return sum(anchors.values()) >= 2 and anchors["variable"]


def _recover_remote_transform(
    source: str,
    recovered_calls: list[tuple[int, int | None, bytes, str]],
) -> dict[str, object]:
    """復号済みIEX断片とsource定数からresponse変換recipeを拘束する。"""

    fragments = [text for _, flag, _, text in recovered_calls if flag == 1]
    has_base64 = any(
        re.search(r"(?i)\[convert\]::frombase64string\s*\(", value)
        for value in fragments
    )
    has_ascii = any(
        re.search(r"(?i)\[text\.encoding\]::ascii\.getstring\s*\(", value)
        for value in fragments
    )
    slices: list[tuple[str, str]] = []
    for value in fragments:
        match = re.search(
            rf"(?i)\.substring\s*\(\s*\$({_IDENTIFIER})\s*,\s*\$({_IDENTIFIER})\s*\)",
            value,
        )
        if match is not None:
            slices.append((match.group(1), match.group(2)))
    if not has_base64 or not has_ascii or len(slices) != 1:
        return {
            "status": "not_recovered",
            "base64_stage_present": has_base64,
            "ascii_stage_present": has_ascii,
            "substring_stage_count": len(slices),
        }
    offset_name, length_name = slices[0]

    def literal_values(name: str) -> list[int]:
        return [
            int(value)
            for value in re.findall(rf"(?i)\${re.escape(name)}\s*=\s*(\d+)\b", source)
        ]

    offsets = literal_values(offset_name)
    lengths = literal_values(length_name)
    if len(offsets) != 1 or len(lengths) != 1:
        return {
            "status": "ambiguous_literal_bounds",
            "base64_stage_present": True,
            "ascii_stage_present": True,
            "substring_stage_count": 1,
            "offset_literal_count": len(offsets),
            "length_literal_count": len(lengths),
        }
    offset = offsets[0]
    length = lengths[0]
    if length <= 0 or offset > 64 * 1024 * 1024 or length > 32 * 1024 * 1024:
        return {
            "status": "literal_bounds_rejected",
            "base64_stage_present": True,
            "ascii_stage_present": True,
            "substring_stage_count": 1,
        }
    return {
        "status": "recovered",
        "operations": ["strict_base64", "dotnet_ascii_replacement", "substring"],
        "substring_offset": offset,
        "substring_length": length,
        "minimum_decoded_characters": offset + length,
        "remote_content_retrieved": False,
        "terminal_payload_recovered": False,
    }


def recover_remote_payload_from_transform(
    data: bytes,
    transform: dict[str, object],
    *,
    limits: RemotePayloadTransformLimits = DEFAULT_REMOTE_LIMITS,
) -> tuple[dict[str, object], bytes | None]:
    """取得済みresponseへ、検証済みBase64/ASCII/substring recipeを適用する。"""

    report: dict[str, object] = {
        "schema_version": 1,
        "profile": "powershell-cyclic-xor-remote-payload-v1",
        "status": "rejected",
        "input_size": len(data),
        "input_sha256": _sha256(data),
        "limits": asdict(limits),
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "powershell_started": False,
            "general_expression_evaluator_used": False,
            "raw_payload_included": False,
        },
    }
    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    if not data or len(data) > limits.max_input_bytes:
        report["status"] = "input_size_rejected"
        return report, None
    expected_operations = ["strict_base64", "dotnet_ascii_replacement", "substring"]
    if (
        transform.get("status") != "recovered"
        or transform.get("operations") != expected_operations
        or not isinstance(transform.get("substring_offset"), int)
        or not isinstance(transform.get("substring_length"), int)
    ):
        report["status"] = "transform_contract_rejected"
        return report, None
    offset = transform["substring_offset"]
    length = transform["substring_length"]
    if (
        offset < 0
        or length <= 0
        or length > limits.max_output_bytes
        or offset > limits.max_decoded_bytes
        or offset + length > limits.max_decoded_bytes
    ):
        report["status"] = "transform_bounds_rejected"
        return report, None
    try:
        compact = re.sub(rb"\s+", b"", data)
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        report["status"] = "strict_base64_rejected"
        return report, None
    if not decoded or len(decoded) > limits.max_decoded_bytes:
        report["status"] = "decoded_size_rejected"
        return report, None
    # .NET Encoding.ASCII.GetStringは0x80以上を ``?`` へ置換する。Pythonの
    # strict decodeへ置き換えると実際のPowerShellと結果が異なるため、ここで
    # その決定的な置換だけを明示的に再現する。
    text = "".join(chr(value) if value < 0x80 else "?" for value in decoded)
    if offset + length > len(text):
        report.update(
            {
                "status": "substring_bounds_rejected",
                "decoded_size": len(decoded),
            }
        )
        return report, None
    output = text[offset : offset + length].encode("ascii")
    report.update(
        {
            "status": "payload_recovered",
            "decoded_size": len(decoded),
            "decoded_sha256": _sha256(decoded),
            "substring_offset": offset,
            "substring_length": length,
            "output_size": len(output),
            "output_sha256": _sha256(output),
            "candidate_set_complete": True,
        }
    )
    return report, output


def recover_reviewed_cyclic_xor_context(
    data: bytes,
    *,
    limits: CyclicXorCallLimits = DEFAULT_LIMITS,
) -> CyclicXorContext:
    """限定profileを再検証し、子層解析用contextをmemory内だけに返す。"""

    primary, _artifacts = recover_powershell_cyclic_xor_calls(data, limits=limits)
    context_report: dict[str, object] = {
        "schema_version": 1,
        "status": "parent_profile_rejected",
        "profile": PROFILE_NAME,
        "parent_status": primary.get("status"),
        "key_material_published": False,
        "function_name_published": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    if primary.get("status") != "artifacts_recovered":
        return CyclicXorContext(context_report, None, None)
    decoded = _decode_source(data)
    if decoded is None:
        context_report["status"] = "parent_text_decode_failed"
        return CyclicXorContext(context_report, None, None)
    text, _encoding = decoded
    array_matches = list(_ARRAY_RE.finditer(text))
    if len(array_matches) > limits.max_array_candidates:
        context_report["status"] = "parent_array_limit_exceeded"
        return CyclicXorContext(context_report, None, None)
    arrays = [
        values
        for match in array_matches
        if (values := _parse_numbers(match.group(1), maximum=limits.max_array_items))
        is not None
    ]
    matching_keys: set[bytes] = set()
    for candidate in arrays:
        if not (
            4 <= len(candidate) <= limits.max_key_items
            and all(0 <= value <= 0xFF for value in candidate)
        ):
            continue
        helpers = {
            role
            for numbers in arrays
            if (recovered := _subtract_key(numbers, candidate)) is not None
            and (role := _helper_role(recovered)) is not None
        }
        if helpers == _EXPECTED_HELPER_ROLES:
            matching_keys.add(bytes(candidate))
    if len(matching_keys) != 1:
        context_report["status"] = "parent_key_not_unique"
        return CyclicXorContext(context_report, None, None)
    key = next(iter(matching_keys))
    if len(key) != primary.get("key_size") or _sha256(key) != primary.get("key_sha256"):
        context_report["status"] = "parent_key_evidence_mismatch"
        return CyclicXorContext(context_report, None, None)

    expected_function_hash = primary.get("function_name_sha256")
    function_names = list(dict.fromkeys(_FUNCTION_RE.findall(text)))
    selected_names = [
        name
        for name in function_names
        if _sha256(name.encode()) == expected_function_hash
    ]
    if len(selected_names) != 1:
        context_report["status"] = "parent_function_not_unique"
        return CyclicXorContext(context_report, None, None)
    context_report.update(
        {
            "status": "context_recovered",
            "key_size": len(key),
            "key_sha256": _sha256(key),
            "function_name_sha256": expected_function_hash,
            "remote_payload_transform": primary.get("remote_payload_transform"),
        }
    )
    return CyclicXorContext(context_report, key, selected_names[0])


def recover_powershell_cyclic_xor_calls(
    data: bytes,
    *,
    limits: CyclicXorCallLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """限定profileの定数callだけを復号し、IEX対象断片を返す。"""

    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    if not data or len(data) > limits.max_input_bytes:
        return _base_report(data, limits, status="input_size_rejected"), []
    decoded = _decode_source(data)
    if decoded is None:
        return _base_report(data, limits, status="text_decode_failed"), []
    text, encoding = decoded

    array_matches = list(_ARRAY_RE.finditer(text))
    if len(array_matches) > limits.max_array_candidates:
        report = _base_report(data, limits, status="array_candidate_limit_exceeded")
        report.update(
            {
                "encoding": encoding,
                "candidate_set_truncated": True,
                "array_candidate_count_lower_bound": len(array_matches),
            }
        )
        return report, []
    arrays = [
        (match.start(), values)
        for match in array_matches
        if (values := _parse_numbers(match.group(1), maximum=limits.max_array_items))
        is not None
    ]
    key_candidates = [
        values
        for _, values in arrays
        if 4 <= len(values) <= limits.max_key_items
        and all(0 <= value <= 0xFF for value in values)
    ]
    work_units = len(data)
    matching_keys: list[tuple[list[int], set[str]]] = []
    for key in key_candidates:
        helpers: set[str] = set()
        for _, numbers in arrays:
            if work_units > limits.max_work_units - len(numbers):
                report = _base_report(data, limits, status="work_limit_exceeded")
                report.update(
                    {
                        "encoding": encoding,
                        "candidate_set_truncated": True,
                        "work_units": work_units,
                    }
                )
                return report, []
            work_units += len(numbers)
            recovered = _subtract_key(numbers, key)
            if recovered is not None:
                role = _helper_role(recovered)
                if role is not None:
                    helpers.add(role)
        if helpers == _EXPECTED_HELPER_ROLES:
            matching_keys.append((key, helpers))

    if not matching_keys:
        report = _base_report(data, limits, status="reviewed_helper_profile_not_found")
        report.update(
            {
                "encoding": encoding,
                "candidate_set_complete": True,
                "array_candidate_count": len(arrays),
                "key_candidate_count": len(key_candidates),
                "work_units": work_units,
            }
        )
        return report, []
    unique_keys = {tuple(key) for key, _ in matching_keys}
    if len(unique_keys) != 1:
        report = _base_report(data, limits, status="key_candidate_not_unique")
        report.update(
            {
                "encoding": encoding,
                "candidate_set_complete": True,
                "array_candidate_count": len(arrays),
                "matching_key_count": len(unique_keys),
                "work_units": work_units,
            }
        )
        return report, []
    key = list(next(iter(unique_keys)))

    function_names = list(dict.fromkeys(_FUNCTION_RE.findall(text)))
    if len(function_names) > limits.max_function_names:
        report = _base_report(data, limits, status="function_candidate_limit_exceeded")
        report.update(
            {
                "encoding": encoding,
                "candidate_set_truncated": True,
                "function_name_count_lower_bound": len(function_names),
            }
        )
        return report, []

    per_function: dict[str, list[tuple[int, int | None, bytes, str]]] = {}
    rejections: Counter[str] = Counter()
    for function_name in function_names:
        call_re = re.compile(
            rf"(?i)(?<!function\s)\b{re.escape(function_name)}\s+"
            r"(['\"])([A-Za-z0-9+/=]{8,})\1(?:\s+(\d+))?"
        )
        calls = list(call_re.finditer(text))
        if len(calls) > limits.max_calls_per_function:
            report = _base_report(data, limits, status="call_candidate_limit_exceeded")
            report.update(
                {
                    "encoding": encoding,
                    "candidate_set_truncated": True,
                    "function_name_sha256": _sha256(function_name.encode()),
                    "call_count_lower_bound": len(calls),
                }
            )
            return report, []
        recovered_calls: list[tuple[int, int | None, bytes, str]] = []
        for match in calls:
            encoded = match.group(2)
            if work_units > limits.max_work_units - len(encoded):
                report = _base_report(data, limits, status="work_limit_exceeded")
                report.update(
                    {
                        "encoding": encoding,
                        "candidate_set_truncated": True,
                        "work_units": work_units,
                    }
                )
                return report, []
            work_units += len(encoded)
            clear = _xor_decode(encoded, key, limits)
            if clear is None:
                rejections["base64_or_size_rejected"] += 1
                continue
            clear_text = _printable_text(clear)
            if clear_text is None:
                rejections["non_text_output"] += 1
                continue
            flag = int(match.group(3)) if match.group(3) is not None else None
            recovered_calls.append((match.start(), flag, clear, clear_text))
        if len(recovered_calls) >= 3 and any(
            flag == 1 for _, flag, _, _ in recovered_calls
        ):
            per_function[function_name] = recovered_calls

    if len(per_function) != 1:
        status = (
            "call_profile_not_found" if not per_function else "call_profile_not_unique"
        )
        report = _base_report(data, limits, status=status)
        report.update(
            {
                "encoding": encoding,
                "candidate_set_complete": True,
                "function_name_count": len(function_names),
                "matching_function_count": len(per_function),
                "work_units": work_units,
                "rejections": dict(sorted(rejections.items())),
            }
        )
        return report, []

    function_name, recovered_calls = next(iter(per_function.items()))
    remote_transform = _recover_remote_transform(text, recovered_calls)
    candidates: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    delivery_urls: list[dict[str, object]] = []
    seen_artifacts: set[str] = set()
    for sequence, (_position, flag, clear, clear_text) in enumerate(recovered_calls, 1):
        digest = _sha256(clear)
        is_script = flag == 1 and _looks_like_script_fragment(clear_text)
        role = "decoded_constant"
        if _URL_RE.fullmatch(clear_text):
            role = "delivery_payload_url"
            delivery_urls.append(
                {
                    "url": clear_text,
                    "sha256": digest,
                    "c2_confirmation": False,
                    "network_contacted": False,
                }
            )
        elif is_script:
            role = "iex_script_fragment"
        candidates.append(
            {
                "sequence": sequence,
                "execute_flag": flag,
                "role": role,
                "output_size": len(clear),
                "output_sha256": digest,
                "artifact_emitted": is_script and digest not in seen_artifacts,
            }
        )
        if is_script and digest not in seen_artifacts:
            if len(artifacts) >= limits.max_artifacts:
                report = _base_report(data, limits, status="artifact_limit_exceeded")
                report.update(
                    {
                        "encoding": encoding,
                        "candidate_set_truncated": True,
                        "candidate_count": len(candidates),
                        "work_units": work_units,
                    }
                )
                return report, []
            seen_artifacts.add(digest)
            artifacts.append((f"cyclic-xor-iex-fragment-{sequence:03d}.ps1", clear))

    report = _base_report(data, limits, status="artifacts_recovered")
    report.update(
        {
            "encoding": encoding,
            "candidate_set_complete": True,
            "candidate_count": len(candidates),
            "array_candidate_count": len(arrays),
            "key_candidate_count": len(key_candidates),
            "matching_key_count": 1,
            "key_size": len(key),
            "key_sha256": _sha256(bytes(key)),
            "helper_profile_count": len(_EXPECTED_HELPER_ROLES),
            "helper_profile_roles": sorted(_EXPECTED_HELPER_ROLES),
            "function_name_sha256": _sha256(function_name.encode()),
            "decoded_call_count": len(recovered_calls),
            "iex_artifact_count": len(artifacts),
            "delivery_url_count": len(delivery_urls),
            "delivery_urls": delivery_urls,
            "remote_payload_transform": remote_transform,
            "work_units": work_units,
            "candidates": candidates,
            "rejections": dict(sorted(rejections.items())),
            "evaluation_boundary": {
                "operations_used": [
                    "decimal_array_subtract_cyclic_key",
                    "strict_base64_decode",
                    "bytewise_xor_cyclic_key",
                    "literal_function_call_binding",
                ],
                "powershell_interpretation_performed": False,
                "remote_content_retrieved": False,
            },
        }
    )
    return report, artifacts
