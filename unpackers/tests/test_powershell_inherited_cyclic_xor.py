from __future__ import annotations

import base64
import hashlib

import pytest

from unpackers import powershell_inherited_cyclic_xor as inherited
from unpackers.powershell_inherited_cyclic_xor import (
    InheritedCyclicXorLimits,
    recover_inherited_cyclic_xor_loader,
)

KEY = [13, 7, 21, 4, 19, 8, 3, 11, 2]
HELPERS = (
    "$tickleproof-bxor($nongases)",
    "iex  ",
    "[Convert]::FromBase64String($adoptivdatter)",
    "-join [char[]]$laborhood",
)


def _array(value: str) -> str:
    values = [
        ord(character) + KEY[index % len(KEY)] for index, character in enumerate(value)
    ]
    values.append(KEY[len(value) % len(KEY)])
    return "@(" + ",".join(str(item) for item in values) + ")"


def _encoded(value: bytes) -> str:
    encrypted = bytes(byte ^ KEY[index % len(KEY)] for index, byte in enumerate(value))
    return base64.b64encode(encrypted).decode("ascii")


def _fixture() -> bytes:
    arrays = "\n".join(
        f"$h{index}={_array(value)}" for index, value in enumerate(HELPERS)
    )
    key_source = "@(" + ",".join(str(item) for item in KEY) + ")"
    script = b"$client = New-Object Net.WebClient"
    base64_stage = b"$global:a=[Convert]::FromBase64String($response)"
    ascii_stage = b"$global:b=[Text.Encoding]::ASCII.GetString($a)"
    slice_stage = b"$global:c=$b.substring($offset,$length)"
    return (
        f"$key={key_source}\n{arrays}\n"
        "function Unwrap($adoptivdatter,$havildarship=0){ $x=1 }\n"
        f"Unwrap '{_encoded(b'http://example.invalid/payload.bin')}'\n"
        f"Unwrap '{_encoded(b'Msxml2.ServerXMLHTTP.6.0')}'\n"
        f"Unwrap '{_encoded(script)}' 1\n"
        f"Unwrap '{_encoded(base64_stage)}' 1\n"
        f"Unwrap '{_encoded(ascii_stage)}' 1\n"
        f"$offset=10;$length=7;Unwrap '{_encoded(slice_stage)}' 1\n"
    ).encode()


def _child(*, second_offset: int = 4) -> bytes:
    first = b"$marshal::Copy($buffer,$zero,$destination,4)"
    second = f"$marshal::Copy($buffer,{second_offset},$destination,$remaining)".encode()
    return (
        "$zero=-10+10;$remaining=10-4\n"
        f"Unwrap '{_encoded(b'$x=1')}' 1\n"
        f"Unwrap '{_encoded(first)}' 1\n"
        f"Unwrap '{_encoded(second)}' 1\n"
    ).encode()


def test_inherits_parent_context_and_recovers_contiguous_remote_spans() -> None:
    parent = _fixture()
    response = base64.b64encode(b"ABCDEFGHIJ" + b"PAYLOAD")

    report, artifacts = recover_inherited_cyclic_xor_loader(
        parent,
        _child(),
        response_data=response,
    )

    assert report["status"] == "artifacts_recovered"
    assert report["parent_context"]["status"] == "context_recovered"
    assert report["copy_span_profile_valid"] is True
    assert report["copy_spans"] == [
        {"source_offset": 0, "size": 4},
        {"source_offset": 4, "size": 6},
    ]
    assert report["response_recovery"]["status"] == "native_spans_recovered"
    remote = {name: value for name, value in artifacts if name.startswith("remote-")}
    assert remote == {
        "remote-native-span-01.bin": b"ABCD",
        "remote-native-span-02.bin": b"EFGHIJ",
    }
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False


def test_rejects_unrelated_parent_profile() -> None:
    report, artifacts = recover_inherited_cyclic_xor_loader(b"$x=1", _child())

    assert report["status"] == "parent_context_rejected"
    assert artifacts == []


def test_does_not_recover_noncontiguous_spans() -> None:
    parent = _fixture()
    child = _child(second_offset=5)

    report, artifacts = recover_inherited_cyclic_xor_loader(
        parent,
        child,
        response_data=base64.b64encode(b"ABCDEFGHIJPAYLOAD"),
    )

    assert report["copy_span_profile_valid"] is False
    assert report["response_recovery"]["status"] == "copy_span_profile_rejected"
    assert not any(name.startswith("remote-") for name, _ in artifacts)


def test_key_is_never_exposed_in_report() -> None:
    parent = _fixture()
    report, _artifacts = recover_inherited_cyclic_xor_loader(parent, _child())

    serialized = repr(report)
    assert repr(KEY) not in serialized
    assert report["safety"]["raw_key_included"] is False


def test_rejects_empty_supplied_response_explicitly() -> None:
    report, artifacts = recover_inherited_cyclic_xor_loader(
        _fixture(),
        _child(),
        response_data=b"",
    )

    assert report["response_recovery"]["status"] == "empty_input_rejected"
    assert not any(name.startswith("remote-") for name, _ in artifacts)


def test_remote_spans_share_global_artifact_limit() -> None:
    report, artifacts = recover_inherited_cyclic_xor_loader(
        _fixture(),
        _child(),
        response_data=base64.b64encode(b"ABCDEFGHIJ" + b"PAYLOAD"),
        limits=InheritedCyclicXorLimits(max_artifacts=3),
    )

    assert report["status"] == "artifact_limit_exceeded"
    assert report["candidate_set_truncated"] is True
    assert artifacts == []


def test_routes_two_native_spans_to_reviewed_x86_pair_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[bytes, bytes]] = []

    def fake_recover(loader: bytes, payload: bytes):
        observed.append((loader, payload))
        return (
            {
                "status": "shellcode_recovered",
                "family_attribution_allowed": False,
            },
            [("remcos-polymorphic-xor-shellcode.bin", b"decoded-shellcode")],
        )

    monkeypatch.setattr(
        inherited, "recover_remcos_polymorphic_xor_loader", fake_recover
    )
    report, artifacts = recover_inherited_cyclic_xor_loader(
        _fixture(),
        _child(),
        response_data=base64.b64encode(b"ABCDEFGHIJ" + b"PAYLOAD"),
    )

    assert observed == [(b"ABCD", b"EFGHIJ")]
    assert report["response_recovery"]["polymorphic_xor_loader"]["status"] == (
        "shellcode_recovered"
    )
    assert ("remcos-polymorphic-xor-shellcode.bin", b"decoded-shellcode") in artifacts


def test_normalizes_verified_legacy_prefix_and_zero_padded_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = b"decoded"
    stage = prefix + b"TAIL"

    monkeypatch.setattr(
        inherited,
        "recover_remcos_polymorphic_xor_loader",
        lambda _loader, _payload: (
            {"status": "shellcode_recovered"},
            [("remcos-polymorphic-xor-shellcode.bin", prefix)],
        ),
    )
    monkeypatch.setattr(
        inherited,
        "recover_remcos_native_span_stage",
        lambda _loader, _payload: (
            {
                "status": "stage_recovered",
                "zero_padding_size": 4,
                "recovered_payload_prefix": {
                    "size": len(prefix),
                    "sha256": hashlib.sha256(prefix).hexdigest(),
                },
            },
            [("remcos-native-stage-03.bin", stage)],
        ),
    )

    report, artifacts = recover_inherited_cyclic_xor_loader(
        _fixture(),
        _child(),
        response_data=base64.b64encode(b"ABCDEFGHIJ" + b"PAYLOAD"),
    )

    normalization = report["response_recovery"]["native_stage_normalization"]
    assert normalization["status"] == "single_logical_candidate"
    assert normalization["prefix_relation_verified"] is True
    assert ("remcos-native-stage-03.bin", stage) in artifacts
    assert not any(
        name == "remcos-polymorphic-xor-shellcode.bin" for name, _ in artifacts
    )
