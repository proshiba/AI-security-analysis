"""managed動的プロキシ静的復号器のテスト。"""

from __future__ import annotations

import struct

import pytest

from unpackers.managed_proxy_deobfuscator import (
    analyze_proxy_resources,
    decrypt_eaz_proxy_table,
    parse_proxy_records,
    resource_summary,
)


def _clear_table() -> bytes:
    records = [(0x04000100 + index, 0x06000100 + index) for index in range(8)]
    records.append((0x04000108, 0x46000108))
    return b"".join(struct.pack("<II", *record) for record in records)


def test_proxy_transform_is_symmetric_and_records_are_valid() -> None:
    clear = _clear_table()
    encrypted = decrypt_eaz_proxy_table(clear)
    assert decrypt_eaz_proxy_table(encrypted) == clear
    records = parse_proxy_records(clear)
    assert all(record["valid"] for record in records)
    assert records[-1]["call_kind"] == "callvirt"
    assert records[-1]["target_token"] == "0x06000108"


def test_analyze_proxy_resources_selects_only_consistent_candidate() -> None:
    clear = _clear_table()
    report = analyze_proxy_resources(
        [("noise", b"A" * 72), ("proxy.data", decrypt_eaz_proxy_table(clear))],
        include_records=True,
    )
    assert report["status"] == "matched"
    assert report["profile"] == "eazfuscator_dynamic_proxy_multi_variant"
    candidate = report["candidates"][0]
    assert candidate["transform_profile"] == "eazfuscator_dynamic_proxy_v1"
    assert candidate["record_count"] == 9
    assert candidate["valid_record_ratio"] == 1.0
    assert candidate["callvirt_count"] == 1


def test_analyze_proxy_resources_supports_second_transform_variant() -> None:
    clear = _clear_table()
    encrypted = decrypt_eaz_proxy_table(clear, seed=1_039_778_284, addend=1_651_518_254)
    assert decrypt_eaz_proxy_table(
        encrypted,
        seed=1_039_778_284,
        addend=1_651_518_254,
    ) == clear
    report = analyze_proxy_resources([("proxy-v2.data", encrypted)], include_records=True)
    assert report["status"] == "matched"
    candidate = report["candidates"][0]
    assert candidate["transform_profile"] == "eazfuscator_dynamic_proxy_v2"
    assert candidate["record_count"] == 9
    assert candidate["valid_record_ratio"] == 1.0


@pytest.mark.parametrize("value", [b"", b"123", b"12345678x"])
def test_invalid_proxy_table_length_is_rejected(value: bytes) -> None:
    with pytest.raises(ValueError):
        parse_proxy_records(value)


def test_resource_summary_flags_high_entropy_candidate() -> None:
    report = resource_summary("protected.bin", bytes(range(256)) * 4)
    assert report["size"] == 1024
    assert report["entropy"] == 8.0
    assert report["protected_candidate"] is True


def test_resource_summary_does_not_flag_repetitive_data() -> None:
    report = resource_summary("plain.bin", b"A" * 1024)
    assert report["entropy"] == 0.0
    assert report["protected_candidate"] is False
