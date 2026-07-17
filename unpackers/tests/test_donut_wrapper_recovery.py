"""Tests for the tightly validated Donut XOR wrapper recovery."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from unpackers import donut_wrapper_unpacker as wrapper


def test_repeated_xor_round_trip_and_empty_key() -> None:
    """Round-trip repeated XOR and reject an empty key."""
    data, key = b"payload", b"key"
    assert wrapper.repeated_xor(wrapper.repeated_xor(data, key), key) == data
    with pytest.raises(ValueError):
        wrapper.repeated_xor(data, b"")


def test_recover_validated_wrapper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recover only after every fixed decoded string and Donut shape validate."""
    key = bytes(range(32))
    encoded = bytearray(0x90)
    encoded[:32] = key
    for offset, expected in wrapper.EXPECTED_STRINGS.items():
        encoded[offset : offset + len(expected)] = wrapper.repeated_xor(
            expected, key
        )
    shellcode = b"donut-shellcode".ljust(
        len(encoded) - wrapper.BLOB_OFFSET, b"\0"
    )
    encoded[wrapper.BLOB_OFFSET :] = wrapper.repeated_xor(shellcode, key)
    data = b"MZ" + b"\0" * 62 + encoded
    section = SimpleNamespace(
        Name=b".rdata\0",
        PointerToRawData=64,
        SizeOfRawData=len(encoded),
    )
    monkeypatch.setattr(
        wrapper.pefile,
        "PE",
        lambda **_: SimpleNamespace(sections=[section]),
    )
    monkeypatch.setattr(
        wrapper, "is_donut_shellcode", lambda value: value.startswith(b"donut")
    )
    report, artifacts = wrapper.recover_xor32_donut_wrapper(data)
    assert report["status"] == "donut_shellcode_recovered"
    assert artifacts[0][1].startswith(b"donut-shellcode")


def test_reject_non_pe_and_bad_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject non-PE input and a PE without the observed section structure."""
    assert wrapper.recover_xor32_donut_wrapper(b"data") == (
        {"status": "not_pe"},
        [],
    )
    monkeypatch.setattr(
        wrapper.pefile,
        "PE",
        lambda **_: SimpleNamespace(sections=[]),
    )
    assert wrapper.recover_xor32_donut_wrapper(b"MZ" + b"\0" * 64)[0][
        "status"
    ] == "wrapper_not_detected"
