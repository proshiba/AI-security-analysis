from __future__ import annotations

import base64
import hashlib
import hmac
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import dotnet_rat_config  # noqa: E402


def encrypt_fixture(value: str, master_key: str, salt: bytes) -> str:
    material = hashlib.pbkdf2_hmac("sha1", master_key.encode(), salt, 50_000, 96)
    encryption_key, authentication_key = material[:32], material[32:]
    iv = bytes(range(16))
    padder = PKCS7(128).padder()
    padded = padder.update(value.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    body = iv + ciphertext
    mac = hmac.new(authentication_key, body, hashlib.sha256).digest()
    return base64.b64encode(mac + body).decode()


def literals_for(family: str) -> dict[str, str]:
    profile = dotnet_rat_config.PROFILES[family]
    master_key = "fixture-master-key"
    names = profile["fields"]
    plain = {
        "ports": "7788",
        "hosts": "c2.example.test,",
        "version": "fixture-version",
        "install": "false",
        "pastebin": "null",
        "anti": "false",
        "group": "fixture",
        "certificate": base64.b64encode(b"fixture-certificate").decode(),
    }
    values = {"Key": base64.b64encode(master_key.encode()).decode()}
    values.update(
        {
            names[public]: encrypt_fixture(value, master_key, profile["salt"])
            for public, value in plain.items()
        }
    )
    return values


@pytest.mark.parametrize("family", ["asyncrat", "venomrat"])
def test_recover_uses_family_specific_field_mapping_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
    family: str,
) -> None:
    monkeypatch.setattr(
        dotnet_rat_config,
        "settings_literals",
        lambda *_args, **_kwargs: literals_for(family),
    )
    result = dotnet_rat_config.recover(b"fixture-managed-client", family)
    assert result["config_endpoints"] == [{"host": "c2.example.test", "port": 7788}]
    assert result["version"] == "fixture-version"
    assert result["certificate"]["sha256"] == hashlib.sha256(b"fixture-certificate").hexdigest()
    assert result["certificate"]["certificate_mismatch_excludes_c2"] is False
    assert result["secret_fields_published"] is False
    assert "master" not in str(result)


def test_decrypt_rejects_modified_hmac() -> None:
    master_key = "fixture-master-key"
    salt = dotnet_rat_config.PROFILES["asyncrat"]["salt"]
    encrypted = bytearray(base64.b64decode(encrypt_fixture("value", master_key, salt)))
    encrypted[0] ^= 1
    with pytest.raises(dotnet_rat_config.ConfigRecoveryError, match="HMAC"):
        dotnet_rat_config.decrypt_setting(base64.b64encode(encrypted).decode(), master_key, salt)