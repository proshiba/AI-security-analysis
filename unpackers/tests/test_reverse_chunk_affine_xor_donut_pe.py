"""逆順fragment＋affine XOR Donut wrapperのfail-closedテスト。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from unpackers import reverse_chunk_affine_xor_donut_pe as recovery


def _stored(shellcode: bytes, key: int) -> bytes:
    encrypted = recovery.affine_xor(key, shellcode)
    common = len(encrypted) // recovery.CHUNK_COUNT
    logical = [common, common, common, len(encrypted) - common * 3]
    chunks = []
    cursor = 0
    for size in logical:
        chunks.append(encrypted[cursor : cursor + size])
        cursor += size
    section = bytearray(recovery.DATA_PREFIX_SIZE)
    for index, chunk in enumerate(reversed(chunks)):
        section.extend(chunk)
        if index + 1 < recovery.CHUNK_COUNT:
            section.extend(bytes((-len(section)) % recovery.CHUNK_ALIGNMENT))
    return bytes(section)


def _fixture(shellcode: bytes, key: int = 0x7C) -> bytes:
    data_section = bytearray(_stored(shellcode, key))
    data_section.extend(bytes((-len(data_section)) % 4))
    metadata = bytes([key, 0, 0, 0]) + len(shellcode).to_bytes(4, "little")
    image = bytearray(b"MZ" + bytes(62))
    image.extend(data_section)
    image.extend(metadata)
    return bytes(image)


def _mock_pe(monkeypatch: pytest.MonkeyPatch, data: bytes, shellcode: bytes) -> None:
    data_size = len(data) - 64
    section = SimpleNamespace(
        Name=b".data\0\0\0",
        PointerToRawData=64,
        SizeOfRawData=data_size,
    )
    monkeypatch.setattr(
        recovery.pefile,
        "PE",
        lambda **_kwargs: SimpleNamespace(sections=[section]),
    )


def test_affine_xor_round_trip_and_key_bound() -> None:
    value = bytes(range(64))
    assert recovery.affine_xor(0x7C, recovery.affine_xor(0x7C, value)) == value
    with pytest.raises(ValueError):
        recovery.affine_xor(0, value)


def test_recovers_validated_reverse_chunk_wrapper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shellcode = b"donut" + bytes(0x1200)
    data = _fixture(shellcode)
    _mock_pe(monkeypatch, data, shellcode)
    monkeypatch.setattr(recovery, "is_donut_shellcode", lambda value: value == shellcode)
    monkeypatch.setattr(
        recovery,
        "decrypt_instance",
        lambda value: (value, SimpleNamespace(name="legacy-test")),
    )
    report, artifacts = recovery.recover_reverse_chunk_affine_xor_donut_pe(data)
    assert report["status"] == "donut_shellcode_recovered"
    assert report["xor_delta"] == -99
    assert report["raw_key_published"] is False
    assert "xor_key" not in report
    assert artifacts == [("reverse-chunk-affine-xor-donut-shellcode", shellcode)]


@pytest.mark.parametrize("mutation", ("prefix", "padding", "metadata", "donut"))
def test_rejects_mutated_wrapper(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    shellcode = b"donut" + bytes(0x1200)
    data = bytearray(_fixture(shellcode))
    if mutation == "prefix":
        data[64] = 1
    elif mutation == "padding":
        common = len(shellcode) // recovery.CHUNK_COUNT
        remainder = len(shellcode) - common * 3
        data[64 + recovery.DATA_PREFIX_SIZE + remainder] = 1
    elif mutation == "metadata":
        data[-7] = 1
    _mock_pe(monkeypatch, bytes(data), shellcode)
    if mutation == "donut":
        monkeypatch.setattr(recovery, "is_donut_shellcode", lambda _value: False)
    assert recovery.recover_reverse_chunk_affine_xor_donut_pe(bytes(data))[1] == []


def test_rejects_non_pe_and_duplicate_data(monkeypatch: pytest.MonkeyPatch) -> None:
    assert recovery.recover_reverse_chunk_affine_xor_donut_pe(b"data") == (
        {"status": "not_pe"},
        [],
    )
    shellcode = b"donut" + bytes(0x1200)
    data = _fixture(shellcode)
    section = SimpleNamespace(
        Name=b".data\0\0\0",
        PointerToRawData=64,
        SizeOfRawData=len(_stored(shellcode, 0x7C)),
    )
    monkeypatch.setattr(
        recovery.pefile,
        "PE",
        lambda **_kwargs: SimpleNamespace(sections=[section, section]),
    )
    assert recovery.recover_reverse_chunk_affine_xor_donut_pe(data)[1] == []
