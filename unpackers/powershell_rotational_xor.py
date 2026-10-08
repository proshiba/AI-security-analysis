"""PowerShellの回転位置付きXOR層を実行せずに復元する。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

MAX_INPUT_SIZE = 16 * 1024 * 1024
MAX_HERE_STRINGS = 32
MAX_BASE64_CHARS = 12 * 1024 * 1024
MAX_DECODED_SIZE = 8 * 1024 * 1024
MAX_DECRYPT_WORK_BYTES = 64 * 1024 * 1024
MIN_ENCRYPTED_SIZE = 256
KEY_SIZE = 32
ROTATION_MODULUS = 7

_HERE_STRING = re.compile(
    r"^[^\S\r\n]*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^\S\r\n]*="
    r"[^\S\r\n]*@'[^\S\r\n]*\r?\n(?P<body>.*?)\r?\n"
    r"[^\S\r\n]*'@[^\S\r\n]*$",
    re.MULTILINE | re.DOTALL,
)
_HERE_STRING_OPENER = re.compile(
    r"^[^\S\r\n]*\$[A-Za-z_][A-Za-z0-9_]*[^\S\r\n]*="
    r"[^\S\r\n]*@'[^\S\r\n]*\r?$",
    re.MULTILINE,
)
_SHAPE_PATTERNS = (
    re.compile(
        r"\$keyPosition\s*=\s*\(\s*\$bytePosition\s*\+\s*"
        r"\$rotationCounter\s*\)\s*%\s*\$cryptoKey\.Length",
        re.IGNORECASE,
    ),
    re.compile(
        r"\$resultBuffer\s*\[\s*\$bytePosition\s*\]\s*=\s*"
        r"\$encryptedData\s*\[\s*\$bytePosition\s*\]\s*-bxor\s*"
        r"\$cryptoKey\s*\[\s*\$keyPosition\s*\]",
        re.IGNORECASE,
    ),
    re.compile(
        r"\$rotationCounter\s*=\s*\(\s*\$rotationCounter\s*\+\s*"
        r"\$cryptoKey\s*\[\s*\$keyPosition\s*\]\s*\)\s*%\s*7",
        re.IGNORECASE,
    ),
)
_SCRIPT_ANCHORS = (
    b"$",
    b"function ",
    b"param(",
    b"param (",
    b"#",
    b"using namespace ",
)


@dataclass(frozen=True)
class RotationalXorRecovery:
    """公開可能な証跡と、隔離保存する復元scriptを保持する。"""

    report: dict[str, object]
    script: bytes | None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_base64(body: str) -> bytes | None:
    compact = re.sub(r"\s+", "", body)
    if not compact or len(compact) > MAX_BASE64_CHARS or len(compact) % 4:
        return None
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or len(decoded) > MAX_DECODED_SIZE:
        return None
    return decoded


def _looks_like_script(value: bytes) -> bool:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text or "\x00" in text:
        return False
    printable = sum(
        character.isprintable() or character in "\r\n\t" for character in text
    )
    if printable / len(text) < 0.98:
        return False
    lowered = value.lstrip().lower()
    return any(lowered.startswith(anchor) for anchor in _SCRIPT_ANCHORS)


def _decrypt(encrypted: bytes, key: bytes) -> bytes:
    output = bytearray(len(encrypted))
    rotation = 0
    for position, value in enumerate(encrypted):
        key_position = (position + rotation) % len(key)
        output[position] = value ^ key[key_position]
        rotation = (rotation + key[key_position]) % ROTATION_MODULUS
    return bytes(output)


def recover_powershell_rotational_xor(data: bytes) -> RotationalXorRecovery:
    """レビュー済みのXOR式と一意な32-byte鍵が揃う場合だけscriptを返す。"""

    base = {
        "schema_version": 1,
        "method": "powershell_rotational_xor_mod7",
        "input_size": len(data),
        "input_sha256": _sha256(data),
        "sample_executed": False,
        "powershell_executed": False,
        "network_contacted": False,
        "raw_key_published": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
        "limits": {
            "maximum_input_bytes": MAX_INPUT_SIZE,
            "maximum_here_strings": MAX_HERE_STRINGS,
            "maximum_base64_characters": MAX_BASE64_CHARS,
            "maximum_decoded_bytes": MAX_DECODED_SIZE,
            "maximum_decrypt_work_bytes": MAX_DECRYPT_WORK_BYTES,
        },
    }
    if not data or len(data) > MAX_INPUT_SIZE:
        return RotationalXorRecovery({**base, "status": "input_size_rejected"}, None)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return RotationalXorRecovery({**base, "status": "text_decode_rejected"}, None)
    if not all(pattern.search(text) for pattern in _SHAPE_PATTERNS):
        return RotationalXorRecovery(
            {**base, "status": "reviewed_xor_shape_not_found"}, None
        )

    for opener_count, _match in enumerate(_HERE_STRING_OPENER.finditer(text), start=1):
        if opener_count > MAX_HERE_STRINGS:
            return RotationalXorRecovery(
                {**base, "status": "here_string_count_rejected"}, None
            )
    entries = list(_HERE_STRING.finditer(text))
    if not entries or len(entries) > MAX_HERE_STRINGS:
        return RotationalXorRecovery(
            {**base, "status": "here_string_count_rejected"}, None
        )
    decoded: list[tuple[str, bytes]] = []
    for match in entries:
        value = _decode_base64(match.group("body"))
        if value is not None:
            decoded.append((match.group("name"), value))
    keys = [(name, value) for name, value in decoded if len(value) == KEY_SIZE]
    ciphertexts = [
        (name, value)
        for name, value in decoded
        if MIN_ENCRYPTED_SIZE <= len(value) <= MAX_DECODED_SIZE
    ]
    candidate: tuple[str, bytes, str, bytes, bytes] | None = None
    candidate_count = 0
    decrypt_work_bytes = 0
    for data_name, encrypted in ciphertexts:
        for key_name, key in keys:
            if data_name == key_name:
                continue
            if decrypt_work_bytes > MAX_DECRYPT_WORK_BYTES - len(encrypted):
                return RotationalXorRecovery(
                    {
                        **base,
                        "status": "decrypt_work_limit_exceeded",
                        "decoded_here_string_count": len(decoded),
                        "candidate_count": candidate_count,
                        "decrypt_work_bytes": decrypt_work_bytes,
                    },
                    None,
                )
            decrypt_work_bytes += len(encrypted)
            clear = _decrypt(encrypted, key)
            if _looks_like_script(clear):
                candidate_count += 1
                if candidate is not None:
                    return RotationalXorRecovery(
                        {
                            **base,
                            "status": "candidate_not_unique",
                            "decoded_here_string_count": len(decoded),
                            "candidate_count": candidate_count,
                            "decrypt_work_bytes": decrypt_work_bytes,
                        },
                        None,
                    )
                candidate = (data_name, encrypted, key_name, key, clear)
    if candidate is None:
        return RotationalXorRecovery(
            {
                **base,
                "status": "validated_output_not_found",
                "decoded_here_string_count": len(decoded),
                "candidate_count": 0,
                "decrypt_work_bytes": decrypt_work_bytes,
            },
            None,
        )
    data_name, encrypted, key_name, key, clear = candidate
    return RotationalXorRecovery(
        {
            **base,
            "status": "script_recovered",
            "encrypted_variable": data_name,
            "key_variable": key_name,
            "encrypted_size": len(encrypted),
            "encrypted_sha256": _sha256(encrypted),
            "key_size": len(key),
            "key_sha256": _sha256(key),
            "rotation_modulus": ROTATION_MODULUS,
            "output_size": len(clear),
            "output_sha256": _sha256(clear),
            "decrypt_work_bytes": decrypt_work_bytes,
            "output_encoding": "utf-8",
            "output_role": "recovered_script_requires_recursive_static_analysis",
        },
        clear,
    )
