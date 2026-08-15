"""StealC v2再構築メモリPE用の静的config extractorテスト。"""

from __future__ import annotations

import base64

from extractors.stealc.v2_memory import (
    LocatedString,
    rc4,
    recover_v2_profile_from_strings,
)


def _encrypted_fixture(
    *,
    base_url: str = "http://192.0.2.10",
    gate_path: str = "/fixture.php",
) -> list[LocatedString]:
    string_key = b"fixtureKey42"
    clear_values = [
        "kernel32.dll",
        "WinHttpSendRequest",
        "WinHttpOpenRequest",
        "WinHttpReceiveResponse",
        base_url,
        gate_path,
        "create",
        "hwid",
        "build",
        "access_token",
        "loader",
        "success",
        "Login Data",
        "Local State",
        "cookies.sqlite",
        "passwords.txt",
        "Steam",
        *[f"fixture_value_{index}" for index in range(48)],
    ]
    values = [
        LocatedString(100, b"8172045377                 "),
        LocatedString(132, b"224b4a27cdb24c8b"),
        LocatedString(156, string_key),
    ]
    offset = 176
    for clear in clear_values:
        encoded = base64.b64encode(rc4(clear.encode("ascii"), string_key))
        values.append(LocatedString(offset, encoded))
        offset += len(encoded) + 4
    return values


def test_recover_v2_memory_profile_and_protocol_keys() -> None:
    profile = recover_v2_profile_from_strings(_encrypted_fixture())
    assert profile is not None
    assert profile.c2_url == "http://192.0.2.10/fixture.php"
    assert profile.build_id == "8172045377"
    assert profile.traffic_key_hex == "224b4a27cdb24c8b"
    assert profile.string_key == "fixtureKey42"
    assert profile.decoded_count >= 50
    assert len(profile.traffic_key_sha256) == 64


def test_rejects_missing_independent_protocol_evidence() -> None:
    values = _encrypted_fixture()
    key = b"fixtureKey42"
    replacement = base64.b64encode(rc4(b"unrelated", key))
    protocol_values = {
        b"create",
        b"hwid",
        b"build",
        b"access_token",
        b"loader",
        b"success",
    }
    rewritten: list[LocatedString] = []
    for item in values:
        clear = None
        if item.offset > 156:
            try:
                clear = rc4(base64.b64decode(item.value, validate=True), key)
            except ValueError:
                pass
        rewritten.append(
            LocatedString(
                item.offset, replacement if clear in protocol_values else item.value
            )
        )
    assert recover_v2_profile_from_strings(rewritten) is None


def test_rejects_base_url_with_path_query_or_fragment() -> None:
    """base URLはscheme、host、任意port以外を受理しない。"""

    for base_url in (
        "http://192.0.2.10/nested",
        "http://192.0.2.10/?campaign=1",
        "http://192.0.2.10/#fragment",
    ):
        assert (
            recover_v2_profile_from_strings(
                _encrypted_fixture(base_url=base_url)
            )
            is None
        )


def test_rejects_gate_path_escape_nested_or_noncanonical_forms() -> None:
    """gateは同一origin直下の単一ASCII PHP名へ限定する。"""

    for gate_path in (
        "//evil.example/collect.php",
        "/../collect.php",
        "/nested/collect.php",
        "/collect.php?campaign=1",
        "/%2e%2e/collect.php",
        "/collect.PHP",
    ):
        assert (
            recover_v2_profile_from_strings(
                _encrypted_fixture(gate_path=gate_path)
            )
            is None
        )


def test_rc4_rejects_empty_key() -> None:
    try:
        rc4(b"ciphertext", b"")
    except ValueError:
        pass
    else:
        raise AssertionError("empty RC4 key must fail")
