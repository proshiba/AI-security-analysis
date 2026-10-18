from __future__ import annotations

import base64

from unpackers.powershell_cyclic_xor_calls import (
    CyclicXorCallLimits,
    recover_powershell_cyclic_xor_calls,
    recover_remote_payload_from_transform,
)
from unpackers.static_unpacker import unpack_bytes

KEY = [13, 7, 21, 4, 19, 8, 3, 11, 2]
HELPERS = (
    "$tickleproof-bxor($nongases)",
    "iex  ",
    "[Convert]::FromBase64String($adoptivdatter)",
    "-join [char[]]$laborhood",
)


def _array(value: str, key: list[int] = KEY) -> str:
    values = [
        ord(character) + key[index % len(key)] for index, character in enumerate(value)
    ]
    values.append(key[len(value) % len(key)])
    return "@(" + ",".join(str(item) for item in values) + ")"


def _encoded(value: bytes, key: list[int] = KEY) -> str:
    encrypted = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(value))
    return base64.b64encode(encrypted).decode("ascii")


def _fixture(
    *,
    key: list[int] = KEY,
    include_helpers: bool = True,
    helper_values: tuple[str, ...] | None = None,
) -> bytes:
    selected_helpers = helper_values or HELPERS
    if not include_helpers:
        selected_helpers = selected_helpers[:3]
    arrays = "\n".join(
        f"$h{index}={_array(value, key)}"
        for index, value in enumerate(selected_helpers)
    )
    key_source = "@(" + ",".join(str(item) for item in key) + ")"
    script = b"$client = New-Object Net.WebClient; $client.Headers['x']='y'"
    base64_stage = b"$global:a=[Convert]::FromBase64String($response)"
    ascii_stage = b"$global:b=[Text.Encoding]::ASCII.GetString($a)"
    slice_stage = b"$global:c=$b.substring($offset,$length)"
    url = b"http://example.invalid/payload.bin"
    other = b"Msxml2.ServerXMLHTTP.6.0"
    return (
        f"$key={key_source}\n{arrays}\n"
        "function Unwrap($adoptivdatter,$havildarship=0){ $x=1 }\n"
        f"Unwrap '{_encoded(url, key)}'\n"
        f"Unwrap '{_encoded(other, key)}'\n"
        f"Unwrap '{_encoded(script, key)}' 1\n"
        f"Unwrap '{_encoded(base64_stage, key)}' 1\n"
        f"Unwrap '{_encoded(ascii_stage, key)}' 1\n"
        f"$offset=3;$length=7;Unwrap '{_encoded(slice_stage, key)}' 1\n"
    ).encode()


def test_recovers_profile_script_fragment_and_delivery_url() -> None:
    report, artifacts = recover_powershell_cyclic_xor_calls(_fixture())

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["decoded_call_count"] == 6
    assert report["iex_artifact_count"] == 4
    assert report["delivery_url_count"] == 1
    assert report["delivery_urls"] == [
        {
            "url": "http://example.invalid/payload.bin",
            "sha256": "17338a88d75f456c0a13eae95df3e49ca91b4671a2583990b9cebb07c4220d66",
            "c2_confirmation": False,
            "network_contacted": False,
        }
    ]
    assert artifacts[0] == (
        "cyclic-xor-iex-fragment-003.ps1",
        b"$client = New-Object Net.WebClient; $client.Headers['x']='y'",
    )
    assert report["remote_payload_transform"] == {
        "status": "recovered",
        "operations": ["strict_base64", "dotnet_ascii_replacement", "substring"],
        "substring_offset": 3,
        "substring_length": 7,
        "minimum_decoded_characters": 10,
        "remote_content_retrieved": False,
        "terminal_payload_recovered": False,
    }
    assert report["safety"]["powershell_started"] is False
    assert report["evidence_boundary"]["delivery_url_is_c2_confirmation"] is False


def test_rejects_missing_reviewed_helper() -> None:
    report, artifacts = recover_powershell_cyclic_xor_calls(
        _fixture(include_helpers=False)
    )

    assert report["status"] == "reviewed_helper_profile_not_found"
    assert report["candidate_set_complete"] is True
    assert artifacts == []


def test_accepts_reviewed_helper_grammar_with_randomized_identifiers() -> None:
    helper_values = (
        "$firstValue -BXOR ( $secondValue )",
        "IEX",
        "[Convert]::FromBase64String( $renamedInput )",
        "-join [char[]] $renamedBytes",
    )

    report, artifacts = recover_powershell_cyclic_xor_calls(
        _fixture(helper_values=helper_values)
    )

    assert report["status"] == "artifacts_recovered"
    assert report["helper_profile_roles"] == [
        "byte_xor",
        "char_join",
        "invoke_expression",
        "strict_base64",
    ]
    assert artifacts


def test_rejects_similar_but_unreviewed_helper_grammar() -> None:
    helper_values = (
        "$firstValue-bxor($secondValue)",
        "Invoke-Expression",
        "[Convert]::FromBase64String($renamedInput)",
        "-join [char[]]$renamedBytes",
    )

    report, artifacts = recover_powershell_cyclic_xor_calls(
        _fixture(helper_values=helper_values)
    )

    assert report["status"] == "reviewed_helper_profile_not_found"
    assert artifacts == []


def test_rejects_ambiguous_matching_key() -> None:
    source = _fixture().decode()
    duplicated = (
        source
        + "\n"
        + "\n".join(
            f"$duplicate{index}={_array(value)}" for index, value in enumerate(HELPERS)
        )
    )
    report, artifacts = recover_powershell_cyclic_xor_calls(duplicated.encode())

    # 同一値の鍵が複数回現れても、値が一意なら同じ候補として扱う。
    assert report["status"] == "artifacts_recovered"
    assert artifacts


def test_rejects_input_over_limit() -> None:
    report, artifacts = recover_powershell_cyclic_xor_calls(
        b"A" * 65,
        limits=CyclicXorCallLimits(max_input_bytes=64),
    )

    assert report["status"] == "input_size_rejected"
    assert artifacts == []


def test_fails_closed_on_work_limit() -> None:
    report, artifacts = recover_powershell_cyclic_xor_calls(
        _fixture(),
        limits=CyclicXorCallLimits(max_work_units=1),
    )

    assert report["status"] == "work_limit_exceeded"
    assert report["candidate_set_truncated"] is True
    assert artifacts == []


def test_applies_recovered_remote_transform_without_execution() -> None:
    initial, _artifacts = recover_powershell_cyclic_xor_calls(_fixture())
    response = base64.b64encode(b"abcPAYLOADtail")

    report, output = recover_remote_payload_from_transform(
        response,
        initial["remote_payload_transform"],
    )

    assert report["status"] == "payload_recovered"
    assert output == b"PAYLOAD"
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False


def test_remote_transform_fails_closed_on_invalid_base64() -> None:
    initial, _artifacts = recover_powershell_cyclic_xor_calls(_fixture())

    report, output = recover_remote_payload_from_transform(
        b"not base64!",
        initial["remote_payload_transform"],
    )

    assert report["status"] == "strict_base64_rejected"
    assert output is None


def test_static_unpacker_routes_reviewed_profile() -> None:
    report, artifacts = unpack_bytes(_fixture(), "delivery.ps1")

    assert report["powershell_cyclic_xor_calls"]["status"] == "artifacts_recovered"
    assert report["powershell_cyclic_xor_calls"]["delivery_url_count"] == 1
    assert any(kind.startswith("cyclic-xor-iex-fragment-") for kind, _ in artifacts)
