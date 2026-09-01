"""Winos LOGININFO offline参照codecの安全境界を検証する。"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE = FRAMEWORK / "malware" / "valleyrat" / "winos_registration.py"


def _load():
    spec = importlib.util.spec_from_file_location("valleyrat_winos_registration", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REGISTRATION = _load()
import winos_protocol  # noqa: E402


def test_public_wide_layout_is_fixed_and_explicitly_not_live() -> None:
    contract = REGISTRATION.registration_contract()
    assert contract["layout_id"] == "winos-public-logininfo-wide-reference-v1"
    assert contract["structure_size"] == 4688
    assert contract["field_count"] == 26
    assert contract["backdoor_offset"] == 4684
    assert contract["sample_bound"] is False
    assert contract["external_send_allowed"] is False
    assert contract["login_token_status"] == "unresolved_requires_exact_sample_review"
    assert contract["safety"]["real_host_information_read"] is False


def test_builds_deterministic_synthetic_logininfo_without_raw_value_output() -> None:
    first = REGISTRATION.build_synthetic_logininfo(
        login_token=0x7E,
        allow_offline_fixture=True,
    )
    second = REGISTRATION.build_synthetic_logininfo(
        login_token=0x7E,
        allow_offline_fixture=True,
    )
    assert first == second
    assert len(first) == 4688
    assert first[0] == 0x7E
    assert first[1] == 0
    result = REGISTRATION.inspect_logininfo_layout(first)
    assert result["structure_valid"] is True
    assert result["nul_terminated_field_count"] == 26
    assert result["padding_zero"] is True
    assert result["backdoor"] is False
    assert result["external_send_allowed"] is False
    assert result["raw_values_published"] is False
    assert "SANDBOX-HOST" not in repr(result)


def test_builds_offline_reference_frame_with_existing_winos_codec() -> None:
    frame = REGISTRATION.build_synthetic_logininfo_frame(
        login_token=0x7E,
        header=b"0123456789",
        allow_offline_fixture=True,
    )
    decoded = winos_protocol.parse_frame(frame)
    assert decoded.complete is True
    assert decoded.declared_length == 14 + REGISTRATION.LOGININFO_SIZE
    assert bytes.fromhex(decoded.payload_hex)[0] == 0x7E


def test_generation_requires_explicit_offline_permission_and_token() -> None:
    with pytest.raises(REGISTRATION.OfflineFixturePermissionError):
        REGISTRATION.build_synthetic_logininfo(login_token=1)
    with pytest.raises(TypeError):
        REGISTRATION.build_synthetic_logininfo(allow_offline_fixture=True)
    with pytest.raises(REGISTRATION.WinosRegistrationError, match="0から255"):
        REGISTRATION.build_synthetic_logininfo(
            login_token=256,
            allow_offline_fixture=True,
        )


def test_unknown_nul_and_overlong_fields_are_rejected() -> None:
    with pytest.raises(REGISTRATION.WinosRegistrationError, match="未定義"):
        REGISTRATION.build_synthetic_logininfo(
            login_token=1,
            fields={"unknown": "value"},
            allow_offline_fixture=True,
        )
    with pytest.raises(REGISTRATION.WinosRegistrationError, match="NUL"):
        REGISTRATION.build_synthetic_logininfo(
            login_token=1,
            fields={"CptName": "bad\x00host"},
            allow_offline_fixture=True,
        )
    with pytest.raises(REGISTRATION.WinosRegistrationError, match="固定長"):
        REGISTRATION.build_synthetic_logininfo(
            login_token=1,
            fields={"IsWebCam": "ABCD"},
            allow_offline_fixture=True,
        )


def test_module_has_no_network_or_real_host_collection_imports() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = {
        node.names[0].name.split(".", 1)[0]
        for node in tree.body
        if isinstance(node, ast.Import)
    }
    imported.update(
        node.module.split(".", 1)[0]
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert imported.isdisjoint(
        {"socket", "ssl", "os", "platform", "subprocess", "winreg", "psutil"}
    )
