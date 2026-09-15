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
    assert result["config_mode"] == "hmac_encrypted"
    assert result["certificate"]["sha256"] == hashlib.sha256(b"fixture-certificate").hexdigest()
    assert result["certificate"]["validation"] == "embedded_certificate_present"
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


def test_recover_accepts_strict_plaintext_asyncrat_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "Key": "<KEY123>",
        "Ports": "443",
        "Hosts": "c2.example.test",
        "Version": "0.5.7B",
        "Install": "false",
        "Pastebin": "null",
        "Anti": "false",
        "Group": "Debug",
        "Certificate": "%Certificate%",
        "Serversignature": "%ServerSignature%",
    }
    monkeypatch.setattr(dotnet_rat_config, "settings_literals", lambda *_args: values)
    monkeypatch.setattr(
        dotnet_rat_config,
        "_asyncrat_plaintext_profile",
        lambda *_args: {
            "settings_initializer": "trivial_return_true",
            "tls_certificate_validation": "accept_all",
            "placeholder_fields_validated": True,
        },
    )

    result = dotnet_rat_config.recover(b"fixture-plaintext-managed-client", "asyncrat")

    assert result["config_mode"] == "plaintext_static_v057b"
    assert result["config_endpoints"] == [{"host": "c2.example.test", "port": 443}]
    assert result["version"] == "0.5.7B"
    assert result["certificate"] == {
        "sha256": None,
        "size": None,
        "validation": "accept_all",
        "certificate_mismatch_excludes_c2": False,
    }
    assert result["crypto_profile"]["settings_storage"] == "plaintext"
    assert result["secret_fields_published"] is False
    assert "<KEY123>" not in str(result)


def test_plaintext_asyncrat_rejects_unreviewed_method_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "Key": "<KEY123>",
        "Ports": "443",
        "Hosts": "c2.example.test",
        "Version": "0.5.7B",
        "Install": "false",
        "Pastebin": "null",
        "Anti": "false",
        "Group": "Debug",
        "Certificate": "%Certificate%",
        "Serversignature": "%ServerSignature%",
    }
    monkeypatch.setattr(dotnet_rat_config, "settings_literals", lambda *_args: values)
    monkeypatch.setattr(
        dotnet_rat_config,
        "_asyncrat_plaintext_profile",
        lambda *_args: (_ for _ in ()).throw(
            dotnet_rat_config.ConfigRecoveryError("既知形状ではありません")
        ),
    )

    with pytest.raises(dotnet_rat_config.ConfigRecoveryError, match="既知形状"):
        dotnet_rat_config.recover(b"fixture-plaintext-managed-client", "asyncrat")


def test_chacha20_ietf_core_matches_rfc8439_block_vector() -> None:
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )

    observed = dotnet_rat_config._chacha20_ietf_crypt(
        bytes(64), key, nonce, counter=1
    )

    assert observed == expected


def test_obfuscated_chacha_wrapper_round_trips_without_publishing_key() -> None:
    master_key = "0123456789abcdef0123456789abcdef"
    nonce = bytes(range(12))
    plaintext = b"c2.example.test"
    ciphertext = dotnet_rat_config._chacha20_ietf_crypt(
        plaintext,
        dotnet_rat_config._derive_obfuscated_chacha_key(master_key),
        nonce,
    )
    encoded = base64.b64encode(nonce + ciphertext).decode()

    assert (
        dotnet_rat_config.decrypt_obfuscated_chacha_setting(encoded, master_key)
        == plaintext.decode()
    )


def test_recover_tries_strict_obfuscated_asyncrat_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"family": "asyncrat", "config_mode": "chacha20_obfuscated_v058"}
    monkeypatch.setattr(
        dotnet_rat_config,
        "settings_literals",
        lambda *_args: (_ for _ in ()).throw(
            dotnet_rat_config.ConfigRecoveryError("型名が難読化されています")
        ),
    )
    monkeypatch.setattr(
        dotnet_rat_config,
        "_recover_obfuscated_chacha_asyncrat",
        lambda _data: expected,
    )

    assert dotnet_rat_config.recover(b"fixture", "asyncrat") is expected
