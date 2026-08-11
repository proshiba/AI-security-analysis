"""RZK low-nibble LECE静的復元のunit test。"""

from __future__ import annotations

import hashlib

import pytest

from unpackers.rzk_lece_unpacker import (
    LECE_MAGIC,
    RZK_HEADER_SIZE,
    _read_bounded_regular_file,
    candidate_report,
    decode_low_nibbles,
    find_rzk_lece_streams,
)
from unpackers.static_unpacker import unpack_bytes


def encode_nibbles(value: bytes) -> bytes:
    return bytes(nibble for item in value for nibble in (item >> 4, item & 0x0F))


def test_recovers_adjacent_streams_and_strips_final_storage_terminator() -> None:
    first = LECE_MAGIC + b"first-envelope"
    second = LECE_MAGIC + b"second-envelope"
    first_header = bytes(range(RZK_HEADER_SIZE))
    second_header = bytes(range(0x80, 0x80 + RZK_HEADER_SIZE))
    carrier = (
        b"prefix"
        + first_header
        + encode_nibbles(first)
        + second_header
        + encode_nibbles(second)
        + b"\x00\x00"
        + b"suffix"
    )

    found = find_rzk_lece_streams(carrier)
    assert [item.data for item in found] == [first, second]
    assert found[0].storage_terminator_size == 0
    assert found[1].storage_terminator_size == 2
    assert found[0].storage_terminator_status == "not_observed"
    assert found[1].storage_terminator_status == "heuristic_ambiguous_removed"
    assert found[0].header_offset == len(b"prefix")
    assert found[1].header_sha256 == hashlib.sha256(second_header).hexdigest()
    report = candidate_report(found)
    assert report[0]["format"] == "rzk-low-nibble-lece-v1"
    assert "header" not in report[0]
    assert report[1]["untrimmed_decoded_size"] == len(second) + 1
    assert report[1]["untrimmed_sha256"] == hashlib.sha256(second + b"\0").hexdigest()


def test_natural_zero_tail_is_reported_as_ambiguous_not_certain_terminator() -> None:
    payload = LECE_MAGIC + b"valid-data-ending-in-zero\0"
    carrier = b"H" * RZK_HEADER_SIZE + encode_nibbles(payload) + b"X"
    found = find_rzk_lece_streams(carrier)
    assert len(found) == 1
    assert found[0].data == payload[:-1]
    assert found[0].storage_terminator_status == "heuristic_ambiguous_removed"
    assert found[0].untrimmed_sha256 == hashlib.sha256(payload).hexdigest()


def test_nonstandard_header_size_never_enables_terminator_heuristic() -> None:
    payload = LECE_MAGIC + b"payload\0"
    carrier = b"H" * 8 + encode_nibbles(payload) + b"X"
    found = find_rzk_lece_streams(carrier, header_size=8)
    assert len(found) == 1
    assert found[0].data == payload
    assert found[0].storage_terminator_status == "not_observed"


def test_rejects_invalid_nibbles_odd_lengths_and_false_magic() -> None:
    with pytest.raises(ValueError):
        decode_low_nibbles(b"")
    with pytest.raises(ValueError):
        decode_low_nibbles(b"\x01")
    with pytest.raises(ValueError):
        decode_low_nibbles(b"\x01\x20")
    assert find_rzk_lece_streams(b"LECE\x01 is not nibble encoded") == []


def test_size_bound_and_header_requirements_fail_closed() -> None:
    encoded = encode_nibbles(LECE_MAGIC + b"payload")
    assert find_rzk_lece_streams(b"x" * (RZK_HEADER_SIZE - 1) + encoded) == []
    capped = b"h" * RZK_HEADER_SIZE + encoded + encode_nibbles(b"more-data") + b"X"
    assert find_rzk_lece_streams(capped, maximum_encoded_size=len(encoded)) == []
    with pytest.raises(ValueError):
        find_rzk_lece_streams(b"anything", header_size=-1)
    with pytest.raises(ValueError):
        find_rzk_lece_streams(b"anything", maximum_encoded_size=1)


def test_cli_reader_rejects_non_regular_oversized_and_reparse_inputs(
    tmp_path, monkeypatch
) -> None:
    with pytest.raises(ValueError, match="通常ファイル"):
        _read_bounded_regular_file(tmp_path, maximum_size=4)

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"12345")
    with pytest.raises(ValueError, match="許容サイズ"):
        _read_bounded_regular_file(sample, maximum_size=4)
    assert _read_bounded_regular_file(sample, maximum_size=5) == b"12345"

    monkeypatch.setattr(type(sample), "is_symlink", lambda _self: True)
    with pytest.raises(ValueError, match="reparse point"):
        _read_bounded_regular_file(sample, maximum_size=8)


def test_static_unpacker_routes_encrypted_container_without_family_inheritance() -> None:
    payload = LECE_MAGIC + b"encrypted-envelope-fixture"
    carrier = b"prefix-rzk-stream-v3" + b"H" * RZK_HEADER_SIZE + encode_nibbles(payload) + b"X"
    report, artifacts = unpack_bytes(carrier, "rzk-carrier.bin")
    assert report["rzk_lece"]["status"] == "encrypted_container_recovered"
    assert report["rzk_lece"]["family_classification"] == "independent_verification_required"
    assert ("rzk-lece-encrypted-container", payload) in artifacts
    assert report["executed"] is False
    assert report["network_contacted"] is False
