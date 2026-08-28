from __future__ import annotations

import base64
import hashlib
import hmac
from types import SimpleNamespace

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
    ciphertext = quasarrat.AES.new(material[:16], quasarrat.AES.MODE_CBC, iv).encrypt(
        encoded + bytes([padding]) * padding
    )
    body = iv + ciphertext
    digest = hmac.new(material[16:], body, hashlib.sha256).digest()
    return base64.b64encode(digest + body).decode("ascii")


def test_authenticated_pbkdf2_aes_round_trip() -> None:
    salt = bytes(range(32))
    encoded = _encrypt("c2.example:2002;", "twenty-character-key", salt, 50_000)

    assert (
        quasarrat.decrypt_authenticated_pbkdf2_aes(
            encoded, "twenty-character-key", salt, 50_000
        )
        == "c2.example:2002;"
    )


def test_authenticated_pbkdf2_aes_rejects_tampering() -> None:
    salt = bytes(range(32))
    blob = bytearray(
        base64.b64decode(_encrypt("1.3.0.0", "twenty-character-key", salt, 50_000))
    )
    blob[-1] ^= 1

    assert (
        quasarrat.decrypt_authenticated_pbkdf2_aes(
            base64.b64encode(blob).decode("ascii"),
            "twenty-character-key",
            salt,
            50_000,
        )
        is None
    )


def test_integrated_dispatcher_uses_specialized_quasarrat_extractor() -> None:
    from extractors.config_extractor import get_extractor

    assert get_extractor("quasarrat") is quasarrat.extract
    assert get_extractor("quasar-rat") is quasarrat.extract


def test_static_candidate_counts_and_total_pbkdf2_attempts_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [SimpleNamespace(Rva=index) for index in range(3)]
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                FieldRva=SimpleNamespace(rows=rows),
            )
        ),
        get_offset_from_rva=lambda value: value,
    )
    assembly = SimpleNamespace(pe=pe, data=b"abc")

    monkeypatch.setattr(quasarrat, "MAXIMUM_SALT_CANDIDATES", 2)
    with pytest.raises(quasarrat._StaticRecoveryLimitError, match="salt候補数"):
        quasarrat._salt_candidates(assembly, lengths=(1,))

    monkeypatch.setattr(quasarrat, "MAXIMUM_ITERATION_CANDIDATES", 2)
    with pytest.raises(quasarrat._StaticRecoveryLimitError, match="iteration候補数"):
        quasarrat._iteration_candidates([1_000, 2_000, 3_000])

    calls = 0

    def reject_candidate(*_args: object) -> None:
        nonlocal calls
        calls += 1

    monkeypatch.setattr(quasarrat, "MAXIMUM_PBKDF2_ATTEMPTS", 2)
    monkeypatch.setattr(
        quasarrat,
        "decrypt_authenticated_pbkdf2_aes",
        reject_candidate,
    )
    with pytest.raises(quasarrat._StaticRecoveryLimitError, match="総試行数"):
        quasarrat._try_decrypt_candidates(
            ["one", "two", "three"],
            "password",
            [b"salt"],
            [50_000],
        )
    assert calls == 2


def test_static_limit_falls_back_and_source_path_is_not_published(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exceed_limit(_data: bytes) -> None:
        raise quasarrat._StaticRecoveryLimitError("limit")

    monkeypatch.setattr(quasarrat, "_recover_config", exceed_limit)
    result = quasarrat.extract(
        b"MZ\x00Quasar.Client",
        r"C:\Users\Alice\SecretCase\sample.exe",
    )

    assert result["config"]["source_name"] == "sample.exe"
    assert result["config"]["decoded_config_recovered"] is False
    assert "Alice" not in repr(result)
    assert "SecretCase" not in repr(result)
