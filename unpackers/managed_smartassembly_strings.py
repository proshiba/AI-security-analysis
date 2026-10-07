"""SmartAssembly系の暗号化resource文字列tableを静的復元する。

検体、CLR、CIL、復元byteは実行しない。CIL/CPU emulationや外部通信も
行わず、raw metadata・CIL・FieldRva・embedded resourceを上限付きで照合する。
復元成功はprotector routeの根拠であり、malware family、C2、実行時到達性を
単独で確定する根拠にはしない。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import time
import zlib
from collections import Counter

import dnfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.error import MethodBodyFormatError
from pefile import PEFormatError

from unpackers.managed_constructor_guard import preflight_clr_declarations
from unpackers.managed_resource_snapshot import (
    prepare_resource_snapshot,
    revalidated_resource_scan,
)

MAX_INPUT = 32 << 20
MAX_METHODS = 4096
MAX_METHOD_BYTES = 256 << 10
MAX_TOTAL_METHOD_BYTES = 8 << 20
MAX_METHOD_INSTRUCTIONS = 20_000
MAX_TOTAL_INSTRUCTIONS = 100_000
MAX_RESOURCES = 256
MAX_RESOURCE_BYTES = 8 << 20
MAX_OUTPUT = 8 << 20
MAX_CHUNKS = 4096
MAX_STRINGS = 4096
MAX_STRING_BYTES = 1 << 20
MAX_STRING_ARTIFACT_BYTES = 8 << 20
MAX_SECONDS = 10.0
SMARTASSEMBLY_MAGIC = 0x7D7A7B


class RecoveryError(ValueError):
    """未知の形、曖昧性、上限超過を安全側へ拒否する。"""


def _base_report(size: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "not_candidate",
        "input_size": size,
        "sample_executed": False,
        "clr_loaded": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_resource_returned": False,
        "decoded_string_artifact_returned": False,
        "runtime_reachability_confirmed": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
    }


def _deadline_check(deadline: float, clock) -> None:
    if clock() > deadline:
        raise RecoveryError("elapsed_time_limit")


def _text(value: object, limit: int = 512) -> str:
    raw = getattr(value, "value", value)
    if not isinstance(raw, str) or len(raw) > limit:
        return ""
    return raw


def _type_name(row: object | None) -> str:
    if row is None:
        return ""
    namespace = _text(getattr(row, "TypeNamespace", None))
    name = _text(getattr(row, "TypeName", None))
    return f"{namespace}.{name}" if namespace and name else name


def _reference_names(tables: object) -> dict[int, str]:
    references: dict[int, str] = {}
    for table_name, prefix in (("TypeRef", 0x01000000), ("TypeDef", 0x02000000)):
        table = getattr(tables, table_name, None)
        for index, row in enumerate(getattr(table, "rows", ()) or (), 1):
            references[prefix | index] = _type_name(row)
    member_table = getattr(tables, "MemberRef", None)
    for index, row in enumerate(getattr(member_table, "rows", ()) or (), 1):
        owner = _type_name(getattr(getattr(row, "Class", None), "row", None))
        name = _text(getattr(row, "Name", None))
        references[0x0A000000 | index] = f"{owner}::{name}" if owner else name
    return references


def _raw_span(pe: object, data: bytes, rva: int, size: int) -> tuple[int, int]:
    if type(rva) is not int or type(size) is not int or rva < 0 or size < 0:
        raise RecoveryError("raw_span_invalid")
    matches: list[tuple[int, int]] = []
    for section in pe.sections:
        virtual = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        raw_offset = int(section.PointerToRawData)
        delta = rva - virtual
        start = raw_offset + delta
        if 0 <= delta and delta + size <= raw_size and 0 <= start <= start + size <= len(data):
            matches.append((start, start + size))
    if len(matches) != 1:
        raise RecoveryError("raw_span_ambiguous_or_unbacked")
    return matches[0]


def _method_window(pe: object, data: bytes, rva: int) -> tuple[int, int]:
    matches: list[tuple[int, int]] = []
    for section in pe.sections:
        virtual = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        delta = rva - virtual
        if 0 <= delta < raw_size:
            available = min(MAX_METHOD_BYTES, raw_size - delta)
            matches.append(_raw_span(pe, data, rva, available))
    if len(matches) != 1:
        raise RecoveryError("method_span_ambiguous_or_unbacked")
    return matches[0]


def _integer(instruction: dict[str, object]) -> int | None:
    opcode = instruction.get("opcode")
    if opcode in {"ldc.i4", "ldc.i4.s"}:
        value = instruction.get("value")
        if type(value) is int:
            return value
        try:
            return int(str(instruction.get("operand") or ""), 0)
        except ValueError:
            return None
    match = re.fullmatch(r"ldc\.i4\.([0-8])", str(opcode))
    if match:
        return int(match.group(1))
    return -1 if opcode == "ldc.i4.m1" else None


def _is_call(instruction: dict[str, object], suffix: str) -> bool:
    return (
        instruction.get("opcode") in {"call", "callvirt", "newobj"}
        and str(instruction.get("resolved") or "").endswith(suffix)
    )


def _normalize_methods(pe: object, data: bytes, deadline: float, clock) -> list[dict[str, object]]:
    tables = pe.net.mdtables
    table = getattr(tables, "MethodDef", None)
    rows = list(getattr(table, "rows", ()) or ())
    if len(rows) > MAX_METHODS:
        raise RecoveryError("method_count_limit")
    references = _reference_names(tables)
    methods: list[dict[str, object]] = []
    total_bytes = 0
    total_instructions = 0
    for index, row in enumerate(rows, 1):
        _deadline_check(deadline, clock)
        rva = int(getattr(row, "Rva", 0) or 0)
        if not rva:
            continue
        begin, end = _method_window(pe, data, rva)
        body = read_method_body_from_bytes(data[begin:end])
        total_bytes += int(body.size)
        total_instructions += len(body.instructions)
        if (
            int(body.size) > MAX_METHOD_BYTES
            or total_bytes > MAX_TOTAL_METHOD_BYTES
            or len(body.instructions) > MAX_METHOD_INSTRUCTIONS
            or total_instructions > MAX_TOTAL_INSTRUCTIONS
        ):
            raise RecoveryError("method_body_budget")
        instructions: list[dict[str, object]] = []
        for item in body.instructions:
            value = getattr(item.operand, "value", None)
            instructions.append(
                {
                    "offset": int(item.offset),
                    "opcode": str(item.opcode.name),
                    "operand": str(item.operand),
                    "value": value if type(value) is int else None,
                    "resolved": references.get(value, "") if type(value) is int else "",
                }
            )
        methods.append(
            {
                "token": 0x06000000 | index,
                "rva": rva,
                "instructions": instructions,
            }
        )
    return methods


def _field_initial_value(pe: object, data: bytes, field_token: int, size: int) -> bytes:
    tables = pe.net.mdtables
    fields = list(getattr(getattr(tables, "Field", None), "rows", ()) or ())
    index = field_token & 0xFFFFFF
    if field_token >> 24 != 4 or not 1 <= index <= len(fields):
        raise RecoveryError("field_token_invalid")
    target = fields[index - 1]
    matches = [
        row
        for row in getattr(getattr(tables, "FieldRva", None), "rows", ()) or ()
        if getattr(getattr(row, "Field", None), "row", None) is target
    ]
    if len(matches) != 1:
        raise RecoveryError("field_rva_mapping_ambiguous")
    begin, end = _raw_span(pe, data, int(matches[0].Rva), size)
    value = data[begin:end]
    if len(value) != size:
        raise RecoveryError("field_initializer_truncated")
    return value


def _resource_bodies(pe: object, data: bytes) -> dict[str, bytes]:
    scan, _resolver, _work = prepare_resource_snapshot(
        data,
        pe,
        max_resources=MAX_RESOURCES,
        max_resource_bytes=MAX_RESOURCE_BYTES,
    )
    scan = revalidated_resource_scan(data, scan)
    coverage = scan.coverage()
    if coverage.get("inventory_complete") is not True:
        raise RecoveryError("resource_inventory_incomplete")
    result: dict[str, bytes] = {}
    total = 0
    for descriptor in scan._descriptors:
        if descriptor.kind != "embedded":
            continue
        if descriptor.body_offset is None or descriptor.body_size is None:
            raise RecoveryError("resource_descriptor_invalid")
        if descriptor.name in result:
            raise RecoveryError("resource_name_ambiguous")
        begin = descriptor.body_offset
        end = begin + descriptor.body_size
        if not 0 <= begin <= end <= len(data):
            raise RecoveryError("resource_body_bounds")
        total += descriptor.body_size
        if descriptor.body_size > MAX_RESOURCE_BYTES or total > MAX_RESOURCE_BYTES:
            raise RecoveryError("resource_byte_budget")
        result[descriptor.name] = data[begin:end]
    return result


def _recipe(methods: list[dict[str, object]]) -> dict[str, object]:
    by_token = {method["token"]: method for method in methods}
    candidates: list[dict[str, object]] = []
    for method in methods:
        token = method.get("token")
        instructions = method.get("instructions")
        if type(token) is not int or not isinstance(instructions, list):
            raise RecoveryError("method_model_invalid")
        if not any(_integer(item) == SMARTASSEMBLY_MAGIC for item in instructions):
            continue
        if not any(
            item.get("opcode") in {"call", "callvirt"} and item.get("value") == token
            for item in instructions
        ):
            continue
        if not any(_is_call(item, "::TransformFinalBlock") for item in instructions):
            continue
        initializers: list[int] = []
        for index in range(len(instructions) - 4):
            window = instructions[index : index + 5]
            field_token = window[3].get("value")
            if (
                _integer(window[0]) == 16
                and window[1].get("opcode") == "newarr"
                and window[1].get("resolved") == "System.Byte"
                and window[2].get("opcode") == "dup"
                and window[3].get("opcode") == "ldtoken"
                and type(field_token) is int
                and field_token >> 24 == 4
                and _is_call(window[4], "RuntimeHelpers::InitializeArray")
            ):
                initializers.append(field_token)
        if len(initializers) != 2 or len(set(initializers)) != 2:
            continue
        helper_tokens = {
            item.get("value")
            for item in instructions
            if item.get("opcode") in {"call", "callvirt", "newobj"}
            and type(item.get("value")) is int
            and item.get("value") >> 24 == 6
            and item.get("value") != token
        }
        helpers = [method, *(by_token[value] for value in helper_tokens if value in by_token)]
        crypto_helpers = []
        for helper in helpers:
            helper_il = helper.get("instructions")
            if not isinstance(helper_il, list):
                continue
            if (
                any(_is_call(item, "RijndaelManaged::.ctor") for item in helper_il)
                and any(_is_call(item, "SymmetricAlgorithm::CreateDecryptor") for item in helper_il)
            ):
                crypto_helpers.append(helper)
        if len({item["token"] for item in crypto_helpers}) != 1:
            continue
        candidates.append(
            {
                "method_token": token,
                "method_rva": method.get("rva"),
                "crypto_helper_token": crypto_helpers[0]["token"],
                "field_tokens": tuple(initializers),
                "normal_cfg_dominance_verified": False,
            }
        )
    if len(candidates) != 1:
        raise RecoveryError("smartassembly_recipe_ambiguous")
    return candidates[0]


def _inflate_raw(payload: bytes, expected: int) -> bytes:
    if not 0 < expected <= MAX_OUTPUT or not payload or len(payload) > MAX_RESOURCE_BYTES:
        raise RecoveryError("deflate_bounds")
    inflater = zlib.decompressobj(-zlib.MAX_WBITS)
    output = inflater.decompress(payload, expected + 1)
    if (
        len(output) != expected
        or not inflater.eof
        or inflater.unused_data
        or inflater.unconsumed_tail
    ):
        raise RecoveryError("deflate_size_or_eof_invalid")
    return output


def _decode_container(
    blob: bytes,
    key: bytes,
    vector: bytes,
    *,
    depth: int = 0,
) -> tuple[bytes, tuple[str, ...]]:
    if type(blob) is not bytes or not 4 <= len(blob) <= MAX_RESOURCE_BYTES or depth > 4:
        raise RecoveryError("container_bounds")
    header = struct.unpack_from("<I", blob)[0]
    if header & 0xFFFFFF != SMARTASSEMBLY_MAGIC:
        raise RecoveryError("container_magic_mismatch")
    kind = header >> 24
    if kind == 3:
        ciphertext = blob[4:]
        if len(key) != 16 or len(vector) != 16 or not ciphertext or len(ciphertext) % 16:
            raise RecoveryError("aes_bounds")
        decryptor = Cipher(algorithms.AES(key), modes.CBC(vector)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        padding = padded[-1]
        if not 1 <= padding <= 16 or padded[-padding:] != bytes([padding]) * padding:
            raise RecoveryError("pkcs7_padding_invalid")
        clear = padded[:-padding]
        output, steps = _decode_container(clear, key, vector, depth=depth + 1)
        return output, ("aes_cbc_pkcs7", *steps)
    if kind != 1 or len(blob) < 16:
        raise RecoveryError("container_kind_unsupported")
    expected_total = struct.unpack_from("<I", blob, 4)[0]
    if not 0 < expected_total <= MAX_OUTPUT:
        raise RecoveryError("container_output_limit")
    position = 8
    chunks = 0
    output = bytearray()
    while position < len(blob):
        if position + 8 > len(blob) or chunks >= MAX_CHUNKS:
            raise RecoveryError("chunk_header_or_count_invalid")
        compressed_size, expanded_size = struct.unpack_from("<II", blob, position)
        position += 8
        if (
            not 0 < compressed_size <= MAX_RESOURCE_BYTES
            or not 0 < expanded_size <= MAX_OUTPUT
            or position + compressed_size > len(blob)
            or len(output) + expanded_size > expected_total
        ):
            raise RecoveryError("chunk_bounds")
        output.extend(_inflate_raw(blob[position : position + compressed_size], expanded_size))
        position += compressed_size
        chunks += 1
    if position != len(blob) or len(output) != expected_total or chunks == 0:
        raise RecoveryError("container_length_mismatch")
    return bytes(output), ("raw_deflate_chunks",)


def _decode_string_table(data: bytes) -> list[dict[str, object]]:
    if type(data) is not bytes or not data or len(data) > MAX_OUTPUT:
        raise RecoveryError("string_table_bounds")
    strings: list[dict[str, object]] = []
    position = 0
    decoded_total = 0
    while position < len(data):
        if len(strings) >= MAX_STRINGS:
            raise RecoveryError("string_count_limit")
        start = position
        first = data[position]
        position += 1
        if first & 0x80 == 0:
            size = first
        elif first & 0x40 == 0:
            if position >= len(data):
                raise RecoveryError("string_length_truncated")
            size = ((first & 0x3F) << 8) | data[position]
            position += 1
        else:
            if position + 3 > len(data):
                raise RecoveryError("string_length_truncated")
            size = (
                ((first & 0x1F) << 24)
                | (data[position] << 16)
                | (data[position + 1] << 8)
                | data[position + 2]
            )
            position += 3
        if size > MAX_STRING_BYTES or position + size > len(data):
            raise RecoveryError("string_body_bounds")
        encoded = data[position : position + size]
        position += size
        try:
            decoded = base64.b64decode(encoded, validate=True)
            value = decoded.decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise RecoveryError("string_base64_or_utf8_invalid") from exc
        decoded_total += len(decoded)
        if decoded_total > MAX_STRING_ARTIFACT_BYTES:
            raise RecoveryError("decoded_string_byte_limit")
        strings.append(
            {
                "offset": start,
                "encoded_size": size,
                "decoded_size": len(decoded),
                "sha256": hashlib.sha256(decoded).hexdigest(),
                "value": value,
            }
        )
    if position != len(data) or not strings:
        raise RecoveryError("string_table_incomplete")
    return strings


_URL = re.compile(r"(?i)^(?:https?|ftp)://[^\s]{1,2048}$")
_HOST_PORT = re.compile(
    r"^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}):([0-9]{1,5})$"
)


def _network_candidates(strings: list[dict[str, object]]) -> list[str]:
    candidates: list[str] = []
    for item in strings:
        value = item["value"]
        if not isinstance(value, str):
            continue
        match = _HOST_PORT.fullmatch(value)
        if (
            _URL.fullmatch(value) or (match and 0 < int(match.group(1)) <= 65535)
        ) and value not in candidates:
            candidates.append(value)
        if len(candidates) >= 256:
            break
    return candidates


def recover_model(
    data: bytes,
    methods: list[dict[str, object]],
    resources: dict[str, bytes],
    field_values: dict[int, bytes],
    *,
    clock=time.monotonic,
    deadline: float | None = None,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """構築済みの有界静的modelを再検証し、文字列JSONだけを返す。"""
    report = _base_report(len(data) if type(data) is bytes else 0)
    if deadline is None:
        deadline = clock() + MAX_SECONDS
    reasons: Counter[str] = Counter()
    try:
        _deadline_check(deadline, clock)
        if type(data) is not bytes or len(data) > MAX_INPUT:
            raise RecoveryError("input_bounds")
        if type(methods) is not list or len(methods) > MAX_METHODS:
            raise RecoveryError("method_model_bounds")
        if type(resources) is not dict or not 0 < len(resources) <= MAX_RESOURCES:
            raise RecoveryError("resource_model_bounds")
        if type(field_values) is not dict or len(field_values) > 4096:
            raise RecoveryError("field_model_bounds")
        total_instructions = 0
        for method in methods:
            if type(method) is not dict:
                raise RecoveryError("method_model_invalid")
            instructions = method.get("instructions")
            if (
                type(method.get("token")) is not int
                or type(method.get("rva")) is not int
                or not isinstance(instructions, list)
                or len(instructions) > MAX_METHOD_INSTRUCTIONS
                or any(type(item) is not dict for item in instructions)
            ):
                raise RecoveryError("method_model_invalid")
            total_instructions += len(instructions)
            if total_instructions > MAX_TOTAL_INSTRUCTIONS:
                raise RecoveryError("method_model_instruction_limit")
        total_resource_bytes = 0
        for name, body in resources.items():
            if (
                type(name) is not str
                or not 0 < len(name) <= 1024
                or type(body) is not bytes
                or len(body) > MAX_RESOURCE_BYTES
            ):
                raise RecoveryError("resource_model_invalid")
            total_resource_bytes += len(body)
            if total_resource_bytes > MAX_RESOURCE_BYTES:
                raise RecoveryError("resource_model_byte_limit")
        if any(
            type(token) is not int or type(value) is not bytes
            for token, value in field_values.items()
        ):
            raise RecoveryError("field_model_invalid")
        recipe = _recipe(methods)
        field_tokens = recipe["field_tokens"]
        if not isinstance(field_tokens, tuple) or len(field_tokens) != 2:
            raise RecoveryError("recipe_field_tokens_invalid")
        fields = []
        for token in field_tokens:
            value = field_values.get(token)
            if type(value) is not bytes or len(value) != 16:
                raise RecoveryError("field_initializer_invalid")
            fields.append(value)
        container_resources = [
            (name, body)
            for name, body in resources.items()
            if (
                type(name) is str
                and 0 < len(name) <= 1024
                and type(body) is bytes
                and 4 <= len(body) <= MAX_RESOURCE_BYTES
                and int.from_bytes(body[:4], "little") & 0xFFFFFF == SMARTASSEMBLY_MAGIC
            )
        ]
        successes: list[dict[str, object]] = []
        for name, body in container_resources:
            for key_index, vector_index in ((0, 1), (1, 0)):
                _deadline_check(deadline, clock)
                try:
                    table, steps = _decode_container(body, fields[key_index], fields[vector_index])
                    strings = _decode_string_table(table)
                except (RecoveryError, ValueError, zlib.error):
                    reasons["candidate_transform_rejected"] += 1
                    continue
                successes.append(
                    {
                        "resource_name": name,
                        "resource": body,
                        "table": table,
                        "strings": strings,
                        "steps": steps,
                        "key_token": field_tokens[key_index],
                        "vector_token": field_tokens[vector_index],
                    }
                )
        if len(successes) != 1:
            raise RecoveryError("decoded_candidate_ambiguous")
        success = successes[0]
        strings = success["strings"]
        if not isinstance(strings, list):
            raise RecoveryError("decoded_string_model_invalid")
        artifact = json.dumps(
            [item["value"] for item in strings],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(artifact) > MAX_STRING_ARTIFACT_BYTES:
            raise RecoveryError("decoded_string_artifact_limit")
        resource = success["resource"]
        table = success["table"]
        if not isinstance(resource, bytes) or not isinstance(table, bytes):
            raise RecoveryError("decoded_candidate_model_invalid")
        report.update(
            {
                "status": "recovered_string_table",
                "sample_sha256": hashlib.sha256(data).hexdigest(),
                "resource_sha256": hashlib.sha256(resource).hexdigest(),
                "resource_size": len(resource),
                "resource_name_sha256": hashlib.sha256(
                    str(success["resource_name"]).encode("utf-8")
                ).hexdigest(),
                "method_token": f"0x{int(recipe['method_token']):08x}",
                "method_rva": f"0x{int(recipe['method_rva']):x}",
                "crypto_helper_token": f"0x{int(recipe['crypto_helper_token']):08x}",
                "key_field_token": f"0x{int(success['key_token']):08x}",
                "vector_field_token": f"0x{int(success['vector_token']):08x}",
                "key_sha256": hashlib.sha256(field_values[int(success["key_token"])]).hexdigest(),
                "vector_sha256": hashlib.sha256(field_values[int(success["vector_token"])]).hexdigest(),
                "transform_steps": list(success["steps"]),
                "string_table_sha256": hashlib.sha256(table).hexdigest(),
                "string_table_size": len(table),
                "decoded_string_count": len(strings),
                "decoded_string_artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                "decoded_string_artifact_size": len(artifact),
                "decoded_string_artifact_returned": True,
                "network_indicator_candidates": _network_candidates(strings),
                "network_indicator_candidates_are_c2_confirmation": False,
                "normal_cfg_dominance_verified": False,
                "reason_counts": dict(sorted(reasons.items())),
                "candidate_only": True,
            }
        )
        return report, [("managed-smartassembly-strings-json", artifact)]
    except RecoveryError as exc:
        report.update(status="rejected", reason=str(exc), reason_counts=dict(sorted(reasons.items())))
        return report, []
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, zlib.error):
        report.update(
            status="rejected",
            reason="invalid_static_model",
            reason_counts=dict(sorted(reasons.items())),
        )
        return report, []


def recover_managed_smartassembly_strings(
    data: bytes,
    *,
    clock=time.monotonic,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """constructor guard後のraw CIL/resourceだけから暗号化文字列tableを復元する。"""
    if type(data) is not bytes or len(data) > MAX_INPUT:
        return recover_model(b"", [], {}, {})
    report = _base_report(len(data))
    preflight = preflight_clr_declarations(data, max_input_bytes=MAX_INPUT)
    report["metadata_preflight"] = preflight
    if preflight.get("accepted") is not True:
        report.update(status="rejected", reason="metadata_preflight_rejected")
        return report, []
    deadline = clock() + MAX_SECONDS
    try:
        pe = dnfile.dnPE(data=data, clr_lazy_load=True)
        methods = _normalize_methods(pe, data, deadline, clock)
        recipe = _recipe(methods)
        field_tokens = recipe["field_tokens"]
        if not isinstance(field_tokens, tuple):
            raise RecoveryError("recipe_field_tokens_invalid")
        fields = {
            token: _field_initial_value(pe, data, token, 16)
            for token in field_tokens
        }
        resources = _resource_bodies(pe, data)
        result, artifacts = recover_model(
            data,
            methods,
            resources,
            fields,
            clock=clock,
            deadline=deadline,
        )
        result["metadata_preflight"] = preflight
        return result, artifacts
    except (
        RecoveryError,
        AttributeError,
        IndexError,
        TypeError,
        ValueError,
        struct.error,
        MethodBodyFormatError,
        PEFormatError,
    ) as exc:
        report.update(
            status="rejected",
            reason=str(exc) if isinstance(exc, RecoveryError) else "invalid_managed_metadata",
        )
        return report, []
