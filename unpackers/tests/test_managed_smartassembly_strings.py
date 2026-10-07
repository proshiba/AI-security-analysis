"""SmartAssembly文字列table復元の人工modelとfail-closed境界を確認する。"""

from __future__ import annotations

import base64
import json
import struct
import zlib

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from unpackers import managed_smartassembly_strings as recovery


def _length(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))
    if value < 0x4000:
        return bytes((0x80 | value >> 8, value & 0xFF))
    if value < 0x20000000:
        return bytes(
            (
                0xC0 | value >> 24,
                value >> 16 & 0xFF,
                value >> 8 & 0xFF,
                value & 0xFF,
            )
        )
    raise ValueError("test string is too large")


def _table(values: list[str]) -> bytes:
    result = bytearray()
    for value in values:
        encoded = base64.b64encode(value.encode("utf-8"))
        result.extend(_length(len(encoded)))
        result.extend(encoded)
    return bytes(result)


def _container(table: bytes, key: bytes, vector: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    compressed = compressor.compress(table) + compressor.flush()
    clear = struct.pack(
        "<IIII",
        0x01000000 | recovery.SMARTASSEMBLY_MAGIC,
        len(table),
        len(compressed),
        len(table),
    ) + compressed
    padding = 16 - len(clear) % 16
    padded = clear + bytes((padding,)) * padding
    encryptor = Cipher(algorithms.AES(key), modes.CBC(vector)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return struct.pack("<I", 0x03000000 | recovery.SMARTASSEMBLY_MAGIC) + ciphertext


def _instruction(opcode: str, *, value=None, resolved="", operand="") -> dict[str, object]:
    return {
        "offset": 0,
        "opcode": opcode,
        "value": value,
        "resolved": resolved,
        "operand": operand,
    }


def _model() -> tuple[list[dict[str, object]], dict[int, bytes]]:
    method_token = 0x06000001
    helper_token = 0x06000002
    first_field = 0x04000001
    second_field = 0x04000002
    initialize = "System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray"
    instructions = [
        _instruction("ldc.i4", operand=str(recovery.SMARTASSEMBLY_MAGIC)),
        _instruction("ldc.i4.s", operand="16"),
        _instruction("newarr", value=0x01000001, resolved="System.Byte"),
        _instruction("dup"),
        _instruction("ldtoken", value=first_field),
        _instruction("call", value=0x0A000001, resolved=initialize),
        _instruction("ldc.i4.s", operand="16"),
        _instruction("newarr", value=0x01000001, resolved="System.Byte"),
        _instruction("dup"),
        _instruction("ldtoken", value=second_field),
        _instruction("call", value=0x0A000001, resolved=initialize),
        _instruction("call", value=helper_token),
        _instruction(
            "callvirt",
            value=0x0A000002,
            resolved=(
                "System.Security.Cryptography.ICryptoTransform::TransformFinalBlock"
            ),
        ),
        _instruction("call", value=method_token),
    ]
    helper = [
        _instruction(
            "newobj",
            value=0x0A000003,
            resolved="System.Security.Cryptography.RijndaelManaged::.ctor",
        ),
        _instruction(
            "callvirt",
            value=0x0A000004,
            resolved=(
                "System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor"
            ),
        ),
    ]
    fields = {
        first_field: bytes.fromhex("00112233445566778899aabbccddeeff"),
        second_field: bytes.fromhex("102132435465768798a9bacbdcedfe0f"),
    }
    return [
        {"token": method_token, "rva": 0x2000, "instructions": instructions},
        {"token": helper_token, "rva": 0x2100, "instructions": helper},
    ], fields


def test_model_recovers_exact_table_and_only_labels_network_candidates():
    values = ["", "decoy UI", "https://example.test/a", "198.51.100.7:443", "日本語"]
    table = _table(values)
    methods, fields = _model()
    body = _container(table, fields[0x04000001], fields[0x04000002])
    report, artifacts = recovery.recover_model(
        b"MZ synthetic managed input",
        methods,
        {"encrypted strings": body},
        fields,
    )
    assert report["status"] == "recovered_string_table"
    assert report["decoded_string_count"] == len(values)
    assert report["network_indicator_candidates"] == [
        "https://example.test/a",
        "198.51.100.7:443",
    ]
    assert report["network_indicator_candidates_are_c2_confirmation"] is False
    assert report["family_attribution_allowed"] is False
    assert report["runtime_reachability_confirmed"] is False
    assert len(artifacts) == 1
    assert artifacts[0][0] == "managed-smartassembly-strings-json"
    assert json.loads(artifacts[0][1]) == values


def test_key_vector_order_is_derived_by_unique_valid_container():
    values = ["one", "two"]
    methods, fields = _model()
    body = _container(
        _table(values),
        fields[0x04000002],
        fields[0x04000001],
    )
    report, artifacts = recovery.recover_model(
        b"MZ reversed key order",
        methods,
        {"strings": body},
        fields,
    )
    assert report["status"] == "recovered_string_table"
    assert report["key_field_token"] == "0x04000002"
    assert json.loads(artifacts[0][1]) == values


def test_two_valid_resources_are_rejected_as_ambiguous():
    methods, fields = _model()
    body = _container(_table(["same"]), fields[0x04000001], fields[0x04000002])
    report, artifacts = recovery.recover_model(
        b"MZ ambiguous resources",
        methods,
        {"first": body, "second": body},
        fields,
    )
    assert report["status"] == "rejected"
    assert report["reason"] == "decoded_candidate_ambiguous"
    assert artifacts == []


def test_recipe_requires_exact_two_distinct_field_initializers():
    methods, fields = _model()
    methods[0]["instructions"][9]["value"] = 0x04000001
    body = _container(_table(["x"]), fields[0x04000001], fields[0x04000002])
    report, artifacts = recovery.recover_model(
        b"MZ duplicate fields",
        methods,
        {"strings": body},
        fields,
    )
    assert report["reason"] == "smartassembly_recipe_ambiguous"
    assert artifacts == []


def test_invalid_base64_and_trailing_deflate_are_rejected():
    with pytest.raises(recovery.RecoveryError, match="base64_or_utf8"):
        recovery._decode_string_table(b"\x04!!!!")
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    payload = compressor.compress(b"ok") + compressor.flush() + b"trailing"
    with pytest.raises(recovery.RecoveryError, match="deflate_size_or_eof"):
        recovery._inflate_raw(payload, 2)


def test_declared_string_length_and_pkcs7_fail_closed():
    with pytest.raises(recovery.RecoveryError, match="string_body_bounds"):
        recovery._decode_string_table(b"\x08YQ==")
    methods, fields = _model()
    body = bytearray(
        _container(_table(["valid"]), fields[0x04000001], fields[0x04000002])
    )
    body[-1] ^= 0x55
    report, artifacts = recovery.recover_model(
        b"MZ bad padding",
        methods,
        {"strings": bytes(body)},
        fields,
    )
    assert report["reason"] == "decoded_candidate_ambiguous"
    assert artifacts == []


def test_untrusted_model_shape_and_nested_instruction_budget_fail_closed():
    report, artifacts = recovery.recover_model(
        b"MZ invalid model",
        [object()],
        {"resource": b"data"},
        {},
    )
    assert report["reason"] == "method_model_invalid"
    assert artifacts == []

    methods, fields = _model()
    methods[0]["instructions"] = [{}] * (recovery.MAX_METHOD_INSTRUCTIONS + 1)
    report, artifacts = recovery.recover_model(
        b"MZ over budget model",
        methods,
        {"resource": b"data"},
        fields,
    )
    assert report["reason"] == "method_model_invalid"
    assert artifacts == []
