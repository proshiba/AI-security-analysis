"""Remcos配布で観測したbase52多段scriptを実行せずに復元する。"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from unpackers.remcos_script_common import (
    is_valid_pe,
    looks_like_powershell,
    sha256_bytes,
    strict_gzip_decompress,
)

MAXIMUM_INPUT_BYTES = 4 * 1024 * 1024
# JavaScript配送層は固定holdoutで8 MiB超まで観測したため、16 MiBを絶対
# 上限とし、固有shapeのraw preflight後にだけ候補を列挙する。
MAXIMUM_JAVASCRIPT_INPUT_BYTES = 16 * 1024 * 1024
MAXIMUM_OUTPUT_BYTES = 16 * 1024 * 1024
MAXIMUM_ARRAYS = 32
MAXIMUM_ALPHABETS = 32
MAXIMUM_PAYLOAD_CANDIDATES = 32
MAXIMUM_BASE52_DECODE_ATTEMPTS = 128
MAXIMUM_BASE52_DECODE_WORK_BYTES = 96 * 1024 * 1024
MAXIMUM_CANDIDATE_ATTEMPTS = 128
MAXIMUM_TRANSFORM_WORK_BYTES = 96 * 1024 * 1024
MINIMUM_ENCODED_CHARACTERS = 90

_JS_ALPHABET = re.compile(
    r"\bvar\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*"
    r"(?P<quote>['\"])(?P<value>[A-Za-z]{52})(?P=quote)\s*;"
)
_JS_ARRAY = re.compile(
    r"\bvar\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*"
    r"\[(?P<body>[0-9A-Fa-fxX,\s]+)\]\s*;"
)
_JS_JOINED_STRINGS = re.compile(
    r"\bvar\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*"
    r"\[(?P<body>[^\[\]]*?)\]"
    r"\s*\.\s*join\s*\(\s*['\"]{2}\s*\)\s*;",
    re.DOTALL,
)
_PS_B64_CALL = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]{0,127}\s*=\s*\[Convert\]::"
    r"['\"]?FromBa`?se64String['\"]?\s*\(\s*"
    r"(?P<quote>['\"])(?P<value>[A-Za-z0-9+/]+={0,2})(?P=quote)\s*\)",
    re.IGNORECASE,
)
_PS_HEX_STRING = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]{0,127}\s*=\s*['\"](?P<value>[0-9A-Fa-f]{32}|[0-9A-Fa-f]{64})['\"]"
)
_PS_LONG_LITERAL = re.compile(
    r"\$[A-Za-z_][A-Za-z0-9_]{0,127}\s*=\s*'(?P<value>[A-Za-z|]{64,})'"
)
_PS_BYTE_ARRAY = re.compile(
    r"\[byte\[\]\]\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]{0,127})\s*=\s*"
    r"(?P<body>(?:0[xX][0-9A-Fa-f]{1,2}\s*,?\s*){8,})",
    re.IGNORECASE,
)

MBIG = 2_147_483_647
MSEED = 161_803_398


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


class DotNetFrameworkRandom:
    """legacy System.Randomの復元に必要な限定実装。"""

    def __init__(self, seed: int) -> None:
        subtraction = MBIG if seed == -2_147_483_648 else abs(seed)
        current = MSEED - subtraction
        if current < 0:
            current += MBIG
        self.seed_array = [0] * 56
        self.seed_array[55] = current
        previous = 1
        for index in range(1, 55):
            slot = (21 * index) % 55
            self.seed_array[slot] = previous
            previous = current - previous
            if previous < 0:
                previous += MBIG
            current = self.seed_array[slot]
        for _round in range(4):
            for index in range(1, 56):
                self.seed_array[index] -= self.seed_array[1 + (index + 30) % 55]
                if self.seed_array[index] < 0:
                    self.seed_array[index] += MBIG
        self.inext = 0
        self.inextp = 21

    def next(self, maximum: int) -> int:
        """0以上maximum未満の値を返す。"""

        self.inext += 1
        if self.inext >= 56:
            self.inext = 1
        self.inextp += 1
        if self.inextp >= 56:
            self.inextp = 1
        value = self.seed_array[self.inext] - self.seed_array[self.inextp]
        if value == MBIG:
            value -= 1
        if value < 0:
            value += MBIG
        self.seed_array[self.inext] = value
        return int((value * (1.0 / MBIG)) * maximum)


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
            "maximum_alphabets": MAXIMUM_ALPHABETS,
            "maximum_payload_candidates": MAXIMUM_PAYLOAD_CANDIDATES,
            "maximum_base52_decode_attempts": MAXIMUM_BASE52_DECODE_ATTEMPTS,
            "maximum_base52_decode_work_bytes": MAXIMUM_BASE52_DECODE_WORK_BYTES,
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
    if re.sub(r"0[xX][0-9A-Fa-f]+|\d+|,|\s+", "", body):
        return None
    values = [_parse_u8_literal(token) for token in tokens]
    if any(value is None for value in values):
        return None
    return bytes(value for value in values if value is not None)


def _javascript_shape_matches(text: str) -> bool:
    patterns = (
        r"\*\s*33\s*\+",
        r"\*\s*48271\s*\)\s*%\s*2147483647",
        r"\*\s*43\s*\)\s*\+",
        r"\*\s*11\s*\)",
        r"\*\s*17\s*\)",
        r"\*\s*23\s*\)",
    )
    return all(re.search(pattern, text) for pattern in patterns) and all(
        marker in text for marker in ("16777216", "65536", ">>>", "<<")
    )


def _javascript_shape_anchor_matches(data: bytes) -> bool:
    """文字列化・候補列挙より前に固有base52復号shapeを確認する。"""

    patterns = (
        rb"\*\s*33\s*\+",
        rb"\*\s*48271\s*\)\s*%\s*2147483647",
        rb"\*\s*43\s*\)\s*\+",
        rb"\*\s*11\s*\)",
        rb"\*\s*17\s*\)",
        rb"\*\s*23\s*\)",
    )
    return all(re.search(pattern, data) for pattern in patterns) and all(
        marker in data for marker in (b"16777216", b"65536", b">>>", b"<<")
    )


def _powershell_shape_anchor_matches(data: bytes) -> bool:
    """PowerShell profileの適用可能性を入力上限判定より先に確認する。"""

    return (
        re.search(rb"transformfinalblock", data, re.IGNORECASE) is not None
        and b"__PLD__" in data
    )


def _incomplete_candidate_report(
    base: dict[str, object], status: str, **details: object
) -> dict[str, object]:
    """候補集合を完査できなかった状態を共通形式で返す。"""

    return {
        **base,
        "status": status,
        "candidate_set_complete": False,
        "candidate_set_truncated": True,
        **details,
    }


def _decode_base52_nine(value: str, alphabet: str) -> bytes | None:
    if len(value) < MINIMUM_ENCODED_CHARACTERS or len(value) % 9:
        return None
    lookup = {character: position for position, character in enumerate(alphabet)}
    output = bytearray()
    try:
        for offset in range(0, len(value), 9):
            accumulator = 0
            for character in value[offset : offset + 9]:
                accumulator = accumulator * 52 + lookup[character]
            output.extend(accumulator.to_bytes(6, "big"))
    except (KeyError, OverflowError):
        return None
    return bytes(output)


def _outer_decrypt(value: bytes, key: bytes) -> bytes | None:
    data = bytearray(value)
    previous = key[0]
    for position, current in enumerate(bytes(data)):
        mask = key[(position + 3) & 15] ^ ((position * 11) & 0xFF) ^ previous
        data[position] = current ^ mask
        previous = (
            previous * 43 + current + key[(position + 7) & 15] + (position & 0xFF)
        ) & 0xFF

    state = list(range(256))
    target = 0
    for position in range(256):
        target = (target + state[position] + key[position & 15]) & 0xFF
        state[position], state[target] = state[target], state[position]
    i = 0
    j = 0
    for position in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        stream = state[(state[i] + state[j] + position) & 0xFF]
        data[position] ^= stream

    for position, current in enumerate(data):
        rotation = (key[(position + 11) & 15] & 3) + 2
        current ^= key[(position + 5) & 15] ^ ((position * 17) & 0xFF)
        current = ((current >> rotation) | (current << (8 - rotation))) & 0xFF
        data[position] = (
            current - key[position & 15] - ((position * 23) & 0xFF)
        ) & 0xFF

    seed = 17
    for current in key:
        seed = (seed * 33 + current) % MBIG
    seed = max(seed, 1)
    sbox = list(range(256))
    state_value = seed
    for position in range(255, 0, -1):
        state_value = (state_value * 48271) % MBIG
        target = state_value % (position + 1)
        sbox[position], sbox[target] = sbox[target], sbox[position]
    inverse = [0] * 256
    for position, current in enumerate(sbox):
        inverse[current] = position
    data = bytearray(inverse[current] for current in data)
    if len(data) < 5:
        return None
    declared = int.from_bytes(data[:4], "big")
    if declared < 1 or declared + 4 != len(data):
        return None
    return bytes(data[4:])


def recover_remcos_javascript_base52(data: bytes) -> RemcosScriptRecovery:
    """base52、feedback、RC4派生、ARX、S-box層からscriptを一意に復元する。"""

    base = _base("remcos_javascript_base52_feedback_rc4_arx", data)
    if not data:
        return RemcosScriptRecovery(
            {**base, "status": "reviewed_shape_not_found"}, None
        )
    if len(data) > MAXIMUM_JAVASCRIPT_INPUT_BYTES:
        return RemcosScriptRecovery(
            _incomplete_candidate_report(base, "input_size_rejected"), None
        )
    if not _javascript_shape_anchor_matches(data):
        return RemcosScriptRecovery(
            {**base, "status": "reviewed_shape_not_found"}, None
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return RemcosScriptRecovery({**base, "status": "text_decode_rejected"}, None)
    if not _javascript_shape_matches(text):
        return RemcosScriptRecovery(
            {**base, "status": "reviewed_shape_not_found"}, None
        )

    alphabets: list[tuple[str, str]] = []
    for alphabet_match_count, match in enumerate(_JS_ALPHABET.finditer(text), start=1):
        if alphabet_match_count > MAXIMUM_ALPHABETS:
            return RemcosScriptRecovery(
                _incomplete_candidate_report(
                    base,
                    "alphabet_count_limit_exceeded",
                    observed_alphabet_count=alphabet_match_count,
                ),
                None,
            )
        if len(set(match.group("value"))) == 52:
            alphabets.append((match.group("name"), match.group("value")))
    keys: list[tuple[str, bytes]] = []
    for array_match_count, match in enumerate(_JS_ARRAY.finditer(text), start=1):
        if array_match_count > MAXIMUM_ARRAYS:
            return RemcosScriptRecovery(
                _incomplete_candidate_report(
                    base,
                    "array_count_rejected",
                    observed_array_count=array_match_count,
                ),
                None,
            )
        value = _parse_byte_values(match.group("body"))
        if value is not None and len(value) == 16:
            keys.append((match.group("name"), value))
    payloads: list[tuple[str, str]] = []
    for payload_match_count, match in enumerate(
        _JS_JOINED_STRINGS.finditer(text), start=1
    ):
        if payload_match_count > MAXIMUM_PAYLOAD_CANDIDATES:
            return RemcosScriptRecovery(
                _incomplete_candidate_report(
                    base,
                    "payload_count_limit_exceeded",
                    observed_payload_count=payload_match_count,
                ),
                None,
            )
        body = re.sub(r"/\*.*?\*/|//[^\r\n]*", "", match.group("body"), flags=re.DOTALL)
        chunks = re.findall(r"['\"]([A-Za-z]+)['\"]", body)
        residue = re.sub(r"['\"][A-Za-z]+['\"]|,|\s+", "", body)
        if residue:
            continue
        combined = "".join(chunks)
        if len(combined) >= MINIMUM_ENCODED_CHARACTERS:
            payloads.append((match.group("name"), combined))

    decode_attempts = len(payloads) * len(alphabets)
    transform_attempts = decode_attempts * len(keys)
    decode_work_bytes = sum(
        (len(encoded) // 9) * 6
        for _payload_name, encoded in payloads
        if len(encoded) % 9 == 0
    ) * len(alphabets)
    transform_work_upper_bound = decode_work_bytes * len(keys)
    candidate_counts = {
        "alphabet_candidate_count": len(alphabets),
        "key_candidate_count": len(keys),
        "payload_candidate_count": len(payloads),
        "planned_decode_attempt_count": decode_attempts,
        "planned_transform_attempt_count": transform_attempts,
        "planned_decode_work_bytes": decode_work_bytes,
        "planned_transform_work_bytes": transform_work_upper_bound,
    }
    if decode_attempts > MAXIMUM_BASE52_DECODE_ATTEMPTS:
        return RemcosScriptRecovery(
            _incomplete_candidate_report(
                base, "base52_decode_attempt_limit_exceeded", **candidate_counts
            ),
            None,
        )
    if transform_attempts > MAXIMUM_CANDIDATE_ATTEMPTS:
        return RemcosScriptRecovery(
            _incomplete_candidate_report(
                base, "candidate_attempt_limit_exceeded", **candidate_counts
            ),
            None,
        )
    if decode_work_bytes > MAXIMUM_BASE52_DECODE_WORK_BYTES:
        return RemcosScriptRecovery(
            _incomplete_candidate_report(
                base, "base52_decode_work_limit_exceeded", **candidate_counts
            ),
            None,
        )
    if transform_work_upper_bound > MAXIMUM_TRANSFORM_WORK_BYTES:
        return RemcosScriptRecovery(
            _incomplete_candidate_report(
                base, "transform_work_limit_exceeded", **candidate_counts
            ),
            None,
        )

    attempts = 0
    work_bytes = 0
    successes: dict[str, tuple[bytes, str, str, str]] = {}
    for payload_name, encoded in payloads:
        for alphabet_name, alphabet in alphabets:
            decoded = _decode_base52_nine(encoded, alphabet)
            if decoded is None:
                continue
            for key_name, key in keys:
                attempts += 1
                if attempts > MAXIMUM_CANDIDATE_ATTEMPTS:
                    return RemcosScriptRecovery(
                        _incomplete_candidate_report(
                            base,
                            "candidate_attempt_limit_exceeded",
                            attempt_count=attempts - 1,
                            **candidate_counts,
                        ),
                        None,
                    )
                if work_bytes > MAXIMUM_TRANSFORM_WORK_BYTES - len(decoded):
                    return RemcosScriptRecovery(
                        _incomplete_candidate_report(
                            base,
                            "transform_work_limit_exceeded",
                            transform_work_bytes=work_bytes,
                            **candidate_counts,
                        ),
                        None,
                    )
                work_bytes += len(decoded)
                script = _outer_decrypt(decoded, key)
                if (
                    script is None
                    or len(script) > MAXIMUM_OUTPUT_BYTES
                    or not looks_like_powershell(script)
                ):
                    continue
                successes[sha256_bytes(script)] = (
                    script,
                    payload_name,
                    alphabet_name,
                    key_name,
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
                **candidate_counts,
            },
            None,
        )
    digest, (script, payload_name, alphabet_name, key_name) = next(
        iter(successes.items())
    )
    key = dict(keys)[key_name]
    return RemcosScriptRecovery(
        {
            **base,
            "status": "powershell_recovered",
            "profile": "javascript_base52_feedback_rc4_arx_sbox_declared_length",
            "payload_variable": payload_name,
            "alphabet_variable": alphabet_name,
            "key_variable": key_name,
            "key_sha256": sha256_bytes(key),
            "output_size": len(script),
            "output_sha256": digest,
            "attempt_count": attempts,
            "transform_work_bytes": work_bytes,
            **candidate_counts,
            "output_role": "recovered_script_requires_recursive_static_analysis",
        },
        script,
    )


def _powershell_stage_shape_matches(text: str) -> bool:
    compact = re.sub(r"\s+", "", text).lower().replace("`", "")
    required = (
        "fromba",
        "se64string",
        "cryptography.a",
        "escryptoserviceprovider",
        "ciphermode]::ecb",
        "paddingmode]::pkcs7",
        "createdecryptor().transformfinalblock",
        "__pld__",
        "-band15",
        "-band31",
        "%7)+1",
    )
    return all(marker in compact for marker in required)


def _terminal_template_shape_matches(text: str) -> bool:
    compact = re.sub(r"\s+", "", text).lower()
    required = (
        "decode-base52stream",
        "restore-shieldedstream",
        "gzipstream",
        "*43",
        "*37",
        "*41",
        "*83",
        "*47",
        "*13",
        "*19",
        "*23",
        "%2147483647",
    )
    return all(marker in compact for marker in required)


def _pkcs7_unpad(value: bytes) -> bytes | None:
    if not value:
        return None
    padding = value[-1]
    if not 1 <= padding <= 16 or value[-padding:] != bytes([padding]) * padding:
        return None
    return value[:-padding]


def _decode_template_candidates(
    text: str,
) -> tuple[list[bytes], list[bytes], list[bytes], list[str]]:
    decoded: list[bytes] = []
    for match in _PS_B64_CALL.finditer(text):
        try:
            value = base64.b64decode(match.group("value"), validate=True)
        except (binascii.Error, ValueError):
            continue
        if value and len(value) <= MAXIMUM_INPUT_BYTES:
            decoded.append(value)
    ciphertexts = [
        value for value in decoded if len(value) >= 16 and len(value) % 16 == 0
    ]
    aes_keys = [value for value in decoded if len(value) == 32]
    hex_values = [
        bytes.fromhex(match.group("value")) for match in _PS_HEX_STRING.finditer(text)
    ]
    transform_keys = [value for value in hex_values if len(value) == 32]
    vectors = [value for value in hex_values if len(value) == 16]
    payloads = [match.group("value") for match in _PS_LONG_LITERAL.finditer(text)]
    return ciphertexts, aes_keys, transform_keys, vectors, payloads


def _decode_base52_stream(value: str) -> bytes | None:
    if (
        len(value) < 2
        or len(value) > MAXIMUM_INPUT_BYTES * 2
        or re.search(r"[^A-Za-z]", value)
    ):
        return None
    tails = {9: 6, 8: 5, 6: 4, 5: 3, 3: 2, 2: 1}
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    lookup = {character: position for position, character in enumerate(alphabet)}
    output = bytearray()
    cursor = 0
    try:
        while cursor < len(value):
            remaining = len(value) - cursor
            width = min(10, remaining)
            byte_count = 7 if width == 10 else tails.get(width)
            if byte_count is None:
                return None
            accumulator = 0
            for character in value[cursor : cursor + width]:
                accumulator = accumulator * 52 + lookup[character]
            output.extend(accumulator.to_bytes(byte_count, "big"))
            if len(output) > MAXIMUM_INPUT_BYTES:
                return None
            cursor += width
    except (KeyError, OverflowError):
        return None
    return bytes(output)


def _restore_shielded(value: bytes, key: bytes, vector: bytes) -> bytes | None:
    data = bytearray(value)
    total = len(data)
    chain_state = vector[0]
    for index, current in enumerate(bytes(data)):
        mask = (
            vector[(index + 7) & 15]
            ^ key[(index + 5) & 31]
            ^ (((index & 0xFF) * 13) & 0xFF)
            ^ chain_state
        )
        data[index] = current ^ mask
        chain_state = (
            chain_state * 43 + current + key[(index + 17) & 31] + (index & 0xFF)
        ) & 0xFF

    state = list(range(256))
    target = 0
    for index in range(256):
        target = (target + state[index] + key[index & 31] + vector[index & 15]) & 0xFF
        state[index], state[target] = state[target], state[index]
    x = 0
    y = 0
    for index in range(total):
        x = (x + 1) & 0xFF
        y = (y + state[x]) & 0xFF
        state[x], state[y] = state[y], state[x]
        data[index] ^= state[(state[x] + state[y] + x) & 0xFF]

    for index, current in enumerate(data):
        rotation = (key[(index + 11) & 31] % 5) + 2
        current ^= vector[index & 15] ^ (((index & 0xFF) * 19) & 0xFF)
        current = ((current >> rotation) | (current << (8 - rotation))) & 0xFF
        data[index] = (
            current - key[index & 31] - (((index & 0xFF) * 23) & 0xFF)
        ) & 0xFF

    for round_number in (1, 0):
        for index in range(0, total - 1, 2):
            left = data[index]
            right = data[index + 1]
            right ^= (left * 83 + key[(index + 1 + round_number * 13) & 31] + 19) & 0xFF
            left ^= (right * 47 + key[(index + round_number * 7) & 31] + 11) & 0xFF
            data[index] = left
            data[index + 1] = right

    seed = 17
    for current in key:
        seed = (seed * 37 + current) % MBIG
    for current in vector:
        seed = (seed * 41 + current) % MBIG
    random = DotNetFrameworkRandom(seed)
    sbox = list(range(256))
    for index in range(255, 0, -1):
        target = random.next(index + 1)
        sbox[index], sbox[target] = sbox[target], sbox[index]
    inverse = [0] * 256
    for index, current in enumerate(sbox):
        inverse[current] = index
    output = bytes(inverse[current] for current in data)
    if output.startswith(b"\x1f\x8b"):
        return strict_gzip_decompress(output, MAXIMUM_OUTPUT_BYTES)
    return output if len(output) <= MAXIMUM_OUTPUT_BYTES else None


def recover_remcos_powershell_base52_pes(data: bytes) -> RemcosPayloadRecovery:
    """AES templateとbase52部品を復元し、一意に妥当なPEだけを返す。"""

    base = _base("remcos_powershell_aes_template_base52_pe", data)
    if not data or not _powershell_shape_anchor_matches(data):
        return RemcosPayloadRecovery({**base, "status": "reviewed_shape_not_found"}, ())
    if len(data) > MAXIMUM_INPUT_BYTES:
        return RemcosPayloadRecovery(
            _incomplete_candidate_report(base, "input_size_rejected"), ()
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return RemcosPayloadRecovery({**base, "status": "text_decode_rejected"}, ())
    if not _powershell_stage_shape_matches(text):
        return RemcosPayloadRecovery({**base, "status": "reviewed_shape_not_found"}, ())

    ciphertexts, aes_keys, transform_keys, vectors, payload_literals = (
        _decode_template_candidates(text)
    )
    attempts = 0
    work_bytes = 0
    templates: dict[str, tuple[bytes, bytes, bytes, bytes, bytes]] = {}
    for encrypted in ciphertexts:
        for aes_key in aes_keys:
            for transform_key in transform_keys:
                for vector in vectors:
                    attempts += 1
                    if attempts > MAXIMUM_CANDIDATE_ATTEMPTS:
                        return RemcosPayloadRecovery(
                            {**base, "status": "candidate_attempt_limit_exceeded"}, ()
                        )
                    if work_bytes > MAXIMUM_TRANSFORM_WORK_BYTES - len(encrypted):
                        return RemcosPayloadRecovery(
                            {
                                **base,
                                "status": "transform_work_limit_exceeded",
                                "transform_work_bytes": work_bytes,
                            },
                            (),
                        )
                    work_bytes += len(encrypted)
                    transformed = bytearray(encrypted)
                    for position, current in enumerate(transformed):
                        current ^= vector[position & 15]
                        rotation = (transform_key[(position + 7) & 31] % 7) + 1
                        current = (
                            (current >> rotation) | (current << (8 - rotation))
                        ) & 0xFF
                        current ^= transform_key[(position + 17) & 31]
                        current ^= transform_key[position & 31]
                        transformed[position] = current
                    decryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).decryptor()
                    clear = _pkcs7_unpad(
                        decryptor.update(bytes(transformed)) + decryptor.finalize()
                    )
                    if clear is None:
                        continue
                    try:
                        template_text = clear.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        continue
                    if (
                        not _terminal_template_shape_matches(template_text)
                        or "__PLD__" not in template_text
                    ):
                        continue
                    templates[sha256_bytes(clear)] = (
                        clear,
                        aes_key,
                        transform_key,
                        vector,
                        encrypted,
                    )
    if len(templates) != 1 or len(payload_literals) != 1:
        return RemcosPayloadRecovery(
            {
                **base,
                "status": "validated_template_not_found"
                if not templates
                else "template_or_payload_not_unique",
                "template_candidate_count": len(templates),
                "payload_literal_count": len(payload_literals),
                "attempt_count": attempts,
                "transform_work_bytes": work_bytes,
            },
            (),
        )

    template_digest, (template, aes_key, transform_key, vector, encrypted_template) = (
        next(iter(templates.items()))
    )
    parts = payload_literals[0].split("|||")
    if len(parts) not in {1, 2}:
        return RemcosPayloadRecovery(
            {**base, "status": "payload_part_count_rejected"}, ()
        )
    template_text = template.decode("utf-8-sig")
    arrays: list[tuple[str, bytes]] = []
    for match in _PS_BYTE_ARRAY.finditer(template_text):
        value = _parse_byte_values(match.group("body"))
        if value is not None:
            arrays.append((match.group("name"), value))
        if len(arrays) > MAXIMUM_ARRAYS:
            return RemcosPayloadRecovery({**base, "status": "array_count_rejected"}, ())
    keys = [(name, value) for name, value in arrays if len(value) == 32]
    vectors2 = [(name, value) for name, value in arrays if len(value) == 16]

    recovered: list[tuple[str, bytes, str, str, str, int]] = []
    for part_index, part in enumerate(parts):
        decoded = _decode_base52_stream(part)
        if decoded is None:
            continue
        part_successes: dict[str, tuple[bytes, str, str]] = {}
        for key_name, key in keys:
            for vector_name, part_vector in vectors2:
                attempts += 1
                if attempts > MAXIMUM_CANDIDATE_ATTEMPTS:
                    return RemcosPayloadRecovery(
                        {**base, "status": "candidate_attempt_limit_exceeded"}, ()
                    )
                if work_bytes > MAXIMUM_TRANSFORM_WORK_BYTES - len(decoded):
                    return RemcosPayloadRecovery(
                        {
                            **base,
                            "status": "transform_work_limit_exceeded",
                            "transform_work_bytes": work_bytes,
                        },
                        (),
                    )
                work_bytes += len(decoded)
                payload = _restore_shielded(decoded, key, part_vector)
                if payload is not None and is_valid_pe(payload):
                    part_successes[sha256_bytes(payload)] = (
                        payload,
                        key_name,
                        vector_name,
                    )
        if len(part_successes) > 1:
            return RemcosPayloadRecovery(
                {
                    **base,
                    "status": "part_candidate_not_unique",
                    "part_index": part_index,
                    "candidate_count": len(part_successes),
                },
                (),
            )
        if part_successes:
            digest, (payload, key_name, vector_name) = next(
                iter(part_successes.items())
            )
            recovered.append(
                (
                    f"remcos-base52-pe-{part_index}",
                    payload,
                    digest,
                    key_name,
                    vector_name,
                    part_index,
                )
            )
    if not recovered:
        return RemcosPayloadRecovery(
            {
                **base,
                "status": "validated_pe_not_found",
                "attempt_count": attempts,
                "transform_work_bytes": work_bytes,
            },
            (),
        )
    if len(recovered) != len(parts):
        return RemcosPayloadRecovery(
            {
                **base,
                "status": "payload_part_recovery_incomplete",
                "payload_part_count": len(parts),
                "recovered_pe_count": len(recovered),
                "recovered_part_indices": [item[5] for item in recovered],
                "partial_recovery_discarded": True,
                "attempt_count": attempts,
                "transform_work_bytes": work_bytes,
            },
            (),
        )

    return RemcosPayloadRecovery(
        {
            **base,
            "status": "pe_recovered",
            "profile": "powershell_aes_template_base52_shielded_stream",
            "template_ciphertext_size": len(encrypted_template),
            "template_sha256": template_digest,
            "aes_key_sha256": sha256_bytes(aes_key),
            "transform_key_sha256": sha256_bytes(transform_key),
            "transform_vector_sha256": sha256_bytes(vector),
            "payload_part_count": len(parts),
            "recovered_pe_count": len(recovered),
            "recovered": [
                {
                    "part_index": part_index,
                    "size": len(payload),
                    "sha256": digest,
                    "key_variable": key_name,
                    "vector_variable": vector_name,
                }
                for (
                    _name,
                    payload,
                    digest,
                    key_name,
                    vector_name,
                    part_index,
                ) in recovered
            ],
            "attempt_count": attempts,
            "transform_work_bytes": work_bytes,
            "output_role": "validated_pes_require_recursive_static_analysis",
        },
        tuple(
            (name, payload)
            for name, payload, _digest, _key, _vector, _part_index in recovered
        ),
    )
