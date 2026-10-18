"""Remcos配布で観測したTEA/RC4および置換表/GZip層を静的復元する。"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from unpackers.remcos_script_common import (
    is_valid_pe,
    looks_like_powershell,
    sha256_bytes,
    strict_gzip_decompress,
)

MAXIMUM_INPUT_BYTES = 4 * 1024 * 1024
# JavaScript配送層は固定holdoutで8 MiB超まで観測した。16 MiBを絶対上限とし、
# 復号候補を列挙する前に固有shapeをraw bytes上で確認する。
MAXIMUM_JAVASCRIPT_INPUT_BYTES = 16 * 1024 * 1024
MAXIMUM_OUTPUT_BYTES = 16 * 1024 * 1024
MAXIMUM_ARRAYS = 32
MAXIMUM_SCALAR_BYTES = 32
MAXIMUM_CANDIDATE_ATTEMPTS = 128
MAXIMUM_TRANSFORM_WORK_BYTES = 64 * 1024 * 1024
MINIMUM_CIPHERTEXT_BYTES = 64

_JS_ARRAY = re.compile(
    r"\bvar\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*"
    r"(?:[A-Za-z_$][A-Za-z0-9_$]{0,127}\s*\(\s*)?"
    r"\[(?P<body>[0-9A-Fa-fxX,\s]+)\]\s*\)?\s*;",
)
_JS_SCALAR = re.compile(
    r"\bvar\s+[A-Za-z_$][A-Za-z0-9_$]{0,127}\s*=\s*(0[xX][0-9A-Fa-f]+|\d+)\s*;"
)
_PS_BASE64 = re.compile(r"(['\"])([A-Za-z0-9+/]{40,}={0,2})\1")
_PS_BYTE_ARRAY = re.compile(
    r"\[byte\[\]\]\s*\$[A-Za-z_][A-Za-z0-9_]{0,127}\s*=\s*@\((?P<body>[^)]*)\)",
    re.IGNORECASE,
)
_PS_XOR_LITERAL = re.compile(r"-bxor\s+(0[xX][0-9A-Fa-f]{1,2}|\d{1,3})\b")


@dataclass(frozen=True)
class RemcosScriptRecovery:
    """公開可能な証跡と、隔離して再帰解析するscriptを保持する。"""

    report: dict[str, object]
    script: bytes | None


@dataclass(frozen=True)
class RemcosPayloadRecovery:
    """公開可能な証跡と、隔離して再帰解析するPE候補を保持する。"""

    report: dict[str, object]
    artifacts: tuple[tuple[str, bytes], ...]


def _base(method: str, data: bytes) -> dict[str, object]:
    return {
        "schema_version": 1,
        "method": method,
        "input_size": len(data),
        "input_sha256": sha256_bytes(data),
        "sample_executed": False,
        "script_executed": False,
        "network_contacted": False,
        "raw_key_published": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
        "limits": {
            "maximum_input_bytes": MAXIMUM_INPUT_BYTES,
            "maximum_javascript_input_bytes": MAXIMUM_JAVASCRIPT_INPUT_BYTES,
            "maximum_output_bytes": MAXIMUM_OUTPUT_BYTES,
            "maximum_arrays": MAXIMUM_ARRAYS,
            "maximum_candidate_attempts": MAXIMUM_CANDIDATE_ATTEMPTS,
            "maximum_transform_work_bytes": MAXIMUM_TRANSFORM_WORK_BYTES,
        },
        "candidate_set_complete": True,
        "candidate_set_truncated": False,
    }


def _parse_u8_literal(value: str) -> int | None:
    """巨大整数を生成せず、0..255のliteralだけを受理する。"""

    if value.lower().startswith("0x"):
        digits = value[2:].lstrip("0") or "0"
        if len(digits) > 2:
            return None
        base = 16
    else:
        digits = value.lstrip("0") or "0"
        if len(digits) > 3:
            return None
        base = 10
    try:
        parsed = int(digits, base)
    except ValueError:
        return None
    return parsed if 0 <= parsed <= 255 else None


def _parse_byte_values(body: str) -> bytes | None:
    tokens = re.findall(r"0[xX][0-9A-Fa-f]+|\d+", body)
    if not tokens or len(tokens) > MAXIMUM_OUTPUT_BYTES:
        return None
    remainder = re.sub(r"0[xX][0-9A-Fa-f]+|\d+|,|\s+", "", body)
    if remainder:
        return None
    values = [_parse_u8_literal(token) for token in tokens]
    if any(value is None for value in values):
        return None
    return bytes(value for value in values if value is not None)


def _rc4(data: bytearray, key: bytes) -> None:
    state = list(range(256))
    target = 0
    for position in range(256):
        target = (target + state[position] + key[position % len(key)]) & 0xFF
        state[position], state[target] = state[target], state[position]
    i = 0
    j = 0
    for position in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        data[position] ^= state[(state[i] + state[j]) & 0xFF]


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _tea_decrypt(data: bytearray, key: bytes) -> None:
    words = [
        int.from_bytes(key[offset : offset + 4], "big") for offset in range(0, 16, 4)
    ]
    for offset in range(0, len(data), 8):
        left = int.from_bytes(data[offset : offset + 4], "big")
        right = int.from_bytes(data[offset + 4 : offset + 8], "big")
        total = 0xE3779B90
        for _round in range(16):
            right = _u32(
                right
                - (
                    _u32((left << 4) + words[2])
                    ^ _u32(left + total)
                    ^ _u32((left >> 5) + words[3])
                )
            )
            left = _u32(
                left
                - (
                    _u32((right << 4) + words[0])
                    ^ _u32(right + total)
                    ^ _u32((right >> 5) + words[1])
                )
            )
            total = _u32(total - 0x9E3779B9)
        data[offset : offset + 4] = left.to_bytes(4, "big")
        data[offset + 4 : offset + 8] = right.to_bytes(4, "big")


def _strict_unpad(value: bytes, block_size: int) -> bytes | None:
    if not value:
        return None
    padding = value[-1]
    if not 1 <= padding <= block_size or value[-padding:] != bytes([padding]) * padding:
        return None
    return value[:-padding]


def _javascript_shape_matches(text: str) -> bool:
    compact = re.sub(r"\s+", "", text).lower()
    required = (
        "0x9e3779b9",
        "0xe3779b90",
        "parseint(",
        "substr",
        ">>>5",
        "<<4",
        "&0xff",
    )
    return (
        all(marker in compact for marker in required)
        and re.search(r"for\([^)]*<0x10;", compact) is not None
    )


def _javascript_shape_anchor_matches(data: bytes) -> bool:
    """大きなJSを文字列化する前に、固有の復号shapeだけを有界確認する。"""

    anchors = (
        rb"0x9e3779b9",
        rb"0xe3779b90",
        rb"parseint\s*\(",
        rb"substr\b",
        rb">>>\s*5",
        rb"<<\s*4",
    )
    return all(re.search(anchor, data, re.IGNORECASE) for anchor in anchors)


def _powershell_shape_anchor_matches(data: bytes) -> bool:
    """PowerShell profileの適用可能性を、入力上限判定より先に確認する。"""

    return (
        re.search(rb"-\s*bnot\b", data, re.IGNORECASE) is not None
        and re.search(rb"compressionmode", data, re.IGNORECASE) is not None
    )


def recover_remcos_javascript_tea_rc4(data: bytes) -> RemcosScriptRecovery:
    """演算shapeと一意な復号結果が一致した場合だけPowerShellを返す。"""

    base = _base("remcos_javascript_rc4_tea_pkcs7", data)
    if not data:
        return RemcosScriptRecovery(
            {**base, "status": "reviewed_shape_not_found"}, None
        )
    if len(data) > MAXIMUM_JAVASCRIPT_INPUT_BYTES:
        return RemcosScriptRecovery(
            {
                **base,
                "status": "input_size_rejected",
                "candidate_set_complete": False,
                "candidate_set_truncated": True,
            },
            None,
        )
    if not _javascript_shape_anchor_matches(data):
        return RemcosScriptRecovery(
            {**base, "status": "reviewed_shape_not_found"}, None
        )
    text = data.decode("latin-1")
    if not _javascript_shape_matches(text):
        return RemcosScriptRecovery(
            {**base, "status": "reviewed_shape_not_found"}, None
        )

    arrays: list[tuple[str, bytes]] = []
    for match in _JS_ARRAY.finditer(text):
        value = _parse_byte_values(match.group("body"))
        if value is not None:
            arrays.append((match.group("name"), value))
        if len(arrays) > MAXIMUM_ARRAYS:
            return RemcosScriptRecovery(
                {
                    **base,
                    "status": "array_count_rejected",
                    "candidate_set_complete": False,
                    "candidate_set_truncated": True,
                },
                None,
            )
    payloads = [
        (name, value)
        for name, value in arrays
        if len(value) >= MINIMUM_CIPHERTEXT_BYTES
    ]
    keys16 = [(name, value) for name, value in arrays if len(value) == 16]
    keys32 = [(name, value) for name, value in arrays if len(value) == 32]
    scalars = {
        value
        for match in _JS_SCALAR.finditer(text)
        if (value := _parse_u8_literal(match.group(1))) is not None
    }
    if not scalars:
        return RemcosScriptRecovery({**base, "status": "scalar_count_rejected"}, None)
    if len(scalars) > MAXIMUM_SCALAR_BYTES:
        return RemcosScriptRecovery(
            {
                **base,
                "status": "scalar_count_rejected",
                "candidate_set_complete": False,
                "candidate_set_truncated": True,
            },
            None,
        )

    successes: dict[str, tuple[bytes, str, str, str, int]] = {}
    attempts = 0
    work_bytes = 0
    for payload_name, encrypted in payloads:
        if len(encrypted) % 8:
            continue
        for key16_name, stored_key16 in keys16:
            for key32_name, stored_key32 in keys32:
                for mask in sorted(scalars):
                    attempts += 1
                    if attempts > MAXIMUM_CANDIDATE_ATTEMPTS:
                        return RemcosScriptRecovery(
                            {
                                **base,
                                "status": "candidate_attempt_limit_exceeded",
                                "attempt_count": attempts - 1,
                                "candidate_set_complete": False,
                                "candidate_set_truncated": True,
                            },
                            None,
                        )
                    if work_bytes > MAXIMUM_TRANSFORM_WORK_BYTES - len(encrypted):
                        return RemcosScriptRecovery(
                            {
                                **base,
                                "status": "transform_work_limit_exceeded",
                                "transform_work_bytes": work_bytes,
                                "candidate_set_complete": False,
                                "candidate_set_truncated": True,
                            },
                            None,
                        )
                    work_bytes += len(encrypted)
                    clear = bytearray(encrypted)
                    key32 = bytes(value ^ mask for value in stored_key32)
                    key16 = bytes(value ^ mask for value in stored_key16)
                    _rc4(clear, key32)
                    _tea_decrypt(clear, key16)
                    script = _strict_unpad(bytes(clear), 8)
                    if (
                        script is None
                        or len(script) > MAXIMUM_OUTPUT_BYTES
                        or not looks_like_powershell(script)
                    ):
                        continue
                    digest = sha256_bytes(script)
                    successes[digest] = (
                        script,
                        payload_name,
                        key16_name,
                        key32_name,
                        mask,
                    )
    if len(successes) != 1:
        return RemcosScriptRecovery(
            {
                **base,
                "status": "validated_output_not_found"
                if not successes
                else "candidate_not_unique",
                "candidate_count": len(successes),
                "attempt_count": attempts,
                "transform_work_bytes": work_bytes,
            },
            None,
        )
    digest, (script, payload_name, key16_name, key32_name, mask) = next(
        iter(successes.items())
    )
    return RemcosScriptRecovery(
        {
            **base,
            "status": "powershell_recovered",
            "profile": "javascript_rc4_then_tea16_pkcs7",
            "payload_variable": payload_name,
            "key16_variable": key16_name,
            "key32_variable": key32_name,
            "mask_sha256": sha256_bytes(bytes([mask])),
            "key16_sha256": sha256_bytes(
                bytes(value ^ mask for value in dict(arrays)[key16_name])
            ),
            "key32_sha256": sha256_bytes(
                bytes(value ^ mask for value in dict(arrays)[key32_name])
            ),
            "output_size": len(script),
            "output_sha256": digest,
            "attempt_count": attempts,
            "transform_work_bytes": work_bytes,
            "output_role": "recovered_script_requires_recursive_static_analysis",
        },
        script,
    )


def _powershell_shape_matches(text: str) -> bool:
    compact = re.sub(r"\s+", "", text).lower().replace("`", "")
    required = (
        "fromba",
        "se64string",
        "-bnot",
        "-band0xff",
        "-band7",
        "-shl",
        "-shr",
        "zipstream",
        "compressionmode",
    )
    return all(marker in compact for marker in required)


def _decode_base64_literals(text: str) -> list[bytes]:
    decoded: dict[str, bytes] = {}
    for match in _PS_BASE64.finditer(text):
        literal = match.group(2)
        if len(literal) > MAXIMUM_INPUT_BYTES * 2:
            continue
        try:
            value = base64.b64decode(literal, validate=True)
        except (binascii.Error, ValueError):
            continue
        if value and len(value) <= MAXIMUM_INPUT_BYTES:
            decoded[sha256_bytes(value)] = value
    return list(decoded.values())


def _transform_table_payload(
    encrypted: bytes,
    rotation_key: bytes,
    xor_key: bytes,
    table: bytes,
    first_constant: int,
    second_constant: int,
) -> bytes | None:
    transformed = bytearray(encrypted)
    for position, original in enumerate(transformed):
        value = table[original]
        value ^= xor_key[position % 32]
        value ^= first_constant
        value = (~value) & 0xFF
        value ^= position & 0xFF
        value ^= second_constant
        rotation = rotation_key[position % 32] & 7
        if rotation:
            value = ((value << rotation) | (value >> (8 - rotation))) & 0xFF
        transformed[position] = value
    return strict_gzip_decompress(bytes(transformed), MAXIMUM_OUTPUT_BYTES)


def recover_remcos_powershell_table_gzip(data: bytes) -> RemcosPayloadRecovery:
    """置換表、2鍵、2定数の演算shapeからGZip内PEを一意に復元する。"""

    base = _base("remcos_powershell_table_transform_gzip", data)
    if not data or not _powershell_shape_anchor_matches(data):
        return RemcosPayloadRecovery({**base, "status": "reviewed_shape_not_found"}, ())
    if len(data) > MAXIMUM_INPUT_BYTES:
        return RemcosPayloadRecovery(
            {
                **base,
                "status": "input_size_rejected",
                "candidate_set_complete": False,
                "candidate_set_truncated": True,
            },
            (),
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return RemcosPayloadRecovery({**base, "status": "text_decode_rejected"}, ())
    if not _powershell_shape_matches(text):
        return RemcosPayloadRecovery({**base, "status": "reviewed_shape_not_found"}, ())

    literals = _decode_base64_literals(text)
    keys = [value for value in literals if len(value) == 32]
    ciphertexts = [
        value for value in literals if len(value) >= MINIMUM_CIPHERTEXT_BYTES
    ]
    tables: list[bytes] = []
    for match in _PS_BYTE_ARRAY.finditer(text):
        table = _parse_byte_values(match.group("body"))
        if table is not None and len(table) == 256 and set(table) == set(range(256)):
            tables.append(table)
        if len(tables) > MAXIMUM_ARRAYS:
            return RemcosPayloadRecovery({**base, "status": "array_count_rejected"}, ())
    constants = {
        value
        for match in _PS_XOR_LITERAL.finditer(text)
        if (value := _parse_u8_literal(match.group(1))) is not None
    }
    if len(constants) < 2 or len(constants) > 8:
        return RemcosPayloadRecovery(
            {**base, "status": "xor_constant_count_rejected"}, ()
        )

    successes: dict[str, tuple[bytes, bytes, bytes, bytes, int, int, bytes]] = {}
    attempts = 0
    work_bytes = 0
    for encrypted in ciphertexts:
        for rotation_key in keys:
            for xor_key in keys:
                if rotation_key == xor_key:
                    continue
                for table in tables:
                    for first_constant in sorted(constants):
                        for second_constant in sorted(constants - {first_constant}):
                            attempts += 1
                            if attempts > MAXIMUM_CANDIDATE_ATTEMPTS:
                                return RemcosPayloadRecovery(
                                    {
                                        **base,
                                        "status": "candidate_attempt_limit_exceeded",
                                        "attempt_count": attempts - 1,
                                    },
                                    (),
                                )
                            if work_bytes > MAXIMUM_TRANSFORM_WORK_BYTES - len(
                                encrypted
                            ):
                                return RemcosPayloadRecovery(
                                    {
                                        **base,
                                        "status": "transform_work_limit_exceeded",
                                        "transform_work_bytes": work_bytes,
                                    },
                                    (),
                                )
                            work_bytes += len(encrypted)
                            payload = _transform_table_payload(
                                encrypted,
                                rotation_key,
                                xor_key,
                                table,
                                first_constant,
                                second_constant,
                            )
                            if payload is None or not is_valid_pe(payload):
                                continue
                            successes[sha256_bytes(payload)] = (
                                payload,
                                rotation_key,
                                xor_key,
                                table,
                                first_constant,
                                second_constant,
                                encrypted,
                            )
    if len(successes) != 1:
        return RemcosPayloadRecovery(
            {
                **base,
                "status": "validated_output_not_found"
                if not successes
                else "candidate_not_unique",
                "candidate_count": len(successes),
                "attempt_count": attempts,
                "transform_work_bytes": work_bytes,
            },
            (),
        )
    (
        digest,
        (
            payload,
            rotation_key,
            xor_key,
            table,
            first_constant,
            second_constant,
            encrypted,
        ),
    ) = next(iter(successes.items()))
    report = {
        **base,
        "status": "pe_recovered",
        "profile": "powershell_substitution_not_index_xor_rotate_gzip",
        "encrypted_size": len(encrypted),
        "rotation_key_sha256": sha256_bytes(rotation_key),
        "xor_key_sha256": sha256_bytes(xor_key),
        "table_sha256": sha256_bytes(table),
        "xor_constant_sha256": [
            sha256_bytes(bytes([first_constant])),
            sha256_bytes(bytes([second_constant])),
        ],
        "output_size": len(payload),
        "output_sha256": digest,
        "attempt_count": attempts,
        "transform_work_bytes": work_bytes,
        "output_role": "validated_pe_requires_recursive_static_analysis",
    }
    return RemcosPayloadRecovery(report, (("remcos-table-gzip-pe", payload),))
