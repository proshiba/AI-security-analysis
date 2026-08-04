from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from extractors import quasarrat


pytestmark = pytest.mark.skipif(quasarrat.AES is None, reason="PyCryptodomeが必要です")


def _encrypt(clear: str, password: str, salt: bytes, iterations: int) -> str:
    material = hashlib.pbkdf2_hmac(
        "sha1", password.encode("utf-8"), salt, iterations, dklen=80
    )
    iv = bytes(range(16))
    encoded = clear.encode("utf-8")
    padding = 16 - len(encoded) % 16
    ciphertext = quasarrat.AES.new(
        material[:16], quasarrat.AES.MODE_CBC, iv
    ).encrypt(encoded + bytes([padding]) * padding)
    body = iv + ciphertext
    digest = hmac.new(material[16:], body, hashlib.sha256).digest()
    return base64.b64encode(digest + body).decode("ascii")


def test_authenticated_pbkdf2_aes_round_trip() -> None:
    salt = bytes(range(32))
    encoded = _encrypt("c2.example:2002;", "twenty-character-key", salt, 50_000)

    assert quasarrat.decrypt_authenticated_pbkdf2_aes(
        encoded, "twenty-character-key", salt, 50_000
    ) == "c2.example:2002;"


def test_authenticated_pbkdf2_aes_rejects_tampering() -> None:
    salt = bytes(range(32))
    blob = bytearray(
        base64.b64decode(_encrypt("1.3.0.0", "twenty-character-key", salt, 50_000))
    )
    blob[-1] ^= 1

    assert quasarrat.decrypt_authenticated_pbkdf2_aes(
        base64.b64encode(blob).decode("ascii"),
        "twenty-character-key",
        salt,
        50_000,
    ) is None

def test_integrated_dispatcher_uses_specialized_quasarrat_extractor() -> None:
    from extractors.config_extractor import get_extractor

    assert get_extractor("quasarrat") is quasarrat.extract
    assert get_extractor("quasar-rat") is quasarrat.extract
