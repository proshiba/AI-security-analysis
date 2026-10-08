"""Win32.RMP managed loader設定のprofile拘束・非実行復元テスト。"""

from __future__ import annotations

import base64
import pathlib

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

from unpackers import managed_win32_rmp_loader as loader


def _encrypt(value: str, password: bytes) -> str:
    vector = bytes(range(16))
    key = password + bytes(range(32 - len(password)))
    ciphertext = AES.new(key, AES.MODE_CBC, vector).encrypt(
        pad(value.encode("utf-8"), AES.block_size)
    )
    return base64.b64encode(vector + ciphertext).decode("ascii")


def _arguments(password: bytes) -> list[str]:
    values = [""] * 19
    values[0] = "https://payload.example.test/stage.png"
    values[2] = values[9] = "C:\\Users\\Public\\Downloads\\"
    values[3] = values[10] = "payloadName"
    values[4] = values[6] = "ToolAlias"
    values[8] = "URL"
    values[11] = "js"
    values[12] = "5"
    values[14] = "buildToken"
    values[15] = "0"
    return [_encrypt(value, password) if value else "" for value in values]


def test_recovers_profile_bound_loader_url_without_publishing_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = b"fixture-password"
    monkeypatch.setattr(
        loader,
        "_profile_password",
        lambda _data: (
            password,
            {
                "password_length": len(password),
                "password_sha256": loader._sha256(password),
            },
        ),
    )
    report = loader.recover_win32_rmp_loader_config(
        b"MZ synthetic managed profile",
        _arguments(password),
    )
    assert report["status"] == "loader_configuration_recovered"
    assert report["loader_url_candidates"] == ["https://payload.example.test/stage.png"]
    assert report["loader_url_role"] == "payload_acquisition_candidate"
    assert report["loader_url_is_c2_confirmation"] is False
    assert report["supports_family_attribution"] is False
    assert report["supports_c2_confirmation"] is False
    assert report["published_clear_argument_indices"] == [0]
    assert report["raw_loader_url_published"] is True
    assert report["raw_non_url_argument_values_published"] is False
    assert password.decode() not in repr(report)


def test_argument_presence_profile_mismatch_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = b"fixture-password"
    monkeypatch.setattr(
        loader,
        "_profile_password",
        lambda _data: (password, {"password_sha256": loader._sha256(password)}),
    )
    arguments = _arguments(password)
    arguments[1] = _encrypt("unexpected", password)
    report = loader.recover_win32_rmp_loader_config(b"MZ", arguments)
    assert report["status"] == "rejected"
    assert report["reason"] == "argument_presence_profile_mismatch"
    assert "loader_url_candidates" not in report


def test_unknown_managed_profile_fails_closed() -> None:
    report = loader.recover_win32_rmp_loader_config(b"MZ-not-managed", [""] * 19)
    assert report["status"] == "rejected"
    assert report["supports_family_attribution"] is False
    assert report["supports_c2_confirmation"] is False


def test_malformed_loader_url_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    password = b"fixture-password"
    monkeypatch.setattr(
        loader,
        "_profile_password",
        lambda _data: (password, {"password_sha256": loader._sha256(password)}),
    )
    arguments = _arguments(password)
    arguments[0] = _encrypt("https://[invalid-host/stage", password)
    report = loader.recover_win32_rmp_loader_config(b"MZ", arguments)
    assert report["status"] == "rejected"
    assert report["reason"] == "loader_url_shape_invalid"
    assert "loader_url_candidates" not in report


def test_loader_url_query_is_not_published(monkeypatch: pytest.MonkeyPatch) -> None:
    password = b"fixture-password"
    monkeypatch.setattr(
        loader,
        "_profile_password",
        lambda _data: (password, {"password_sha256": loader._sha256(password)}),
    )
    arguments = _arguments(password)
    secret = "do-not-publish"
    arguments[0] = _encrypt(
        f"https://payload.example.test/stage.png?token={secret}", password
    )

    report = loader.recover_win32_rmp_loader_config(b"MZ", arguments)

    assert report["status"] == "loader_configuration_recovered"
    assert report["loader_url_candidates"] == ["https://payload.example.test/stage.png"]
    assert report["loader_url_query_redacted"] is True
    assert report["raw_loader_url_published"] is False
    assert secret not in repr(report)


def test_resource_transform_is_symmetric_and_bounded() -> None:
    value = bytes(range(127))
    transformed = loader._resource_transform(value, bytes(range(32)))
    assert loader._resource_transform(transformed, bytes(range(32))) == value
    with pytest.raises(loader.RecoveryError, match="resource_transform_bounds"):
        loader._resource_transform(b"", bytes(range(32)))


def test_static_key_recipe_uses_only_harmless_derived_arrays() -> None:
    initial_key = bytes((index * 7 + 3) & 0xFF for index in range(32))
    initial_vector = bytes((index * 11 + 5) & 0xFF for index in range(16))
    token = bytes((index * 13 + 9) & 0xFF for index in range(8))

    derived, vector = loader._combine_resource_transform_key(
        initial_key, initial_vector, token
    )

    expected_vector = bytearray(reversed(initial_vector))
    for index, value in enumerate(token):
        expected_vector[index * 2 + 1] = value
    expected = bytearray(initial_key)
    for index, value in enumerate(expected_vector):
        expected[index] ^= value
    assert loader._sha256(derived) == loader._sha256(bytes(expected))
    assert loader._sha256(vector) == loader._sha256(bytes(expected_vector))
    assert len(derived) == 32
    assert len(vector) == 16


def test_static_key_recipe_rejects_incomplete_or_ambiguous_inputs() -> None:
    with pytest.raises(loader.RecoveryError, match="resource_key_initializer_bounds"):
        loader._combine_resource_transform_key(bytes(31), bytes(16), b"")
    with pytest.raises(loader.RecoveryError, match="assembly_public_key_token_bounds"):
        loader._combine_resource_transform_key(bytes(32), bytes(16), bytes(7))


def test_key_derivation_report_contains_hashes_not_raw_arrays(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial_key = bytes((index * 5 + 1) & 0xFF for index in range(32))
    initial_vector = bytes((index * 3 + 2) & 0xFF for index in range(16))
    token = bytes((index * 17 + 4) & 0xFF for index in range(8))
    recipe = loader._KeyRecipe(3, 1, 5, 6, 14, 12, 101, 202, 303)
    monkeypatch.setattr(loader, "_discover_key_recipe", lambda _data, _pe: recipe)
    monkeypatch.setattr(
        loader,
        "_recover_static_initializers",
        lambda _data, _pe, _recipe: (initial_key, initial_vector, 17),
    )
    monkeypatch.setattr(loader, "_assembly_public_key_token", lambda _pe: token)

    derived, evidence = loader._derive_resource_transform_key(b"MZ fixture", object())

    assert evidence["key_length"] == len(derived) == 32
    assert evidence["key_sha256"] == loader._sha256(derived)
    assert evidence["vector_length"] == 16
    assert evidence["public_key_token_length"] == 8
    assert evidence["visited_state_count"] == 17
    assert evidence["raw_key_material_published"] is False
    rendered = repr(evidence)
    assert initial_key.hex() not in rendered
    assert initial_vector.hex() not in rendered
    assert token.hex() not in rendered


def test_production_module_has_no_fixed_transform_key_constant() -> None:
    source = pathlib.Path(loader.__file__).read_text(encoding="utf-8")
    assert "_RESOURCE_TRANSFORM_KEY" not in source
    assert "bytes.fromhex" not in source


def test_input_type_contract() -> None:
    with pytest.raises(TypeError, match="assemblyはbytes"):
        loader.recover_win32_rmp_loader_config("MZ", [])  # type: ignore[arg-type]
