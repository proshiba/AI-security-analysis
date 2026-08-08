from __future__ import annotations

import hashlib
import struct

import pytest

from malware.formbook_loader.injected_stub import (
    FIRST_MARKER,
    SECOND_MARKER,
    InjectedStubError,
    derive_primary_key,
    derive_secondary_key,
    find_unique_marker,
    module_relative_calls,
    recover_stub,
    x86_score,
    xloader_decrypt,
)


def test_key_derivation_is_stable_without_publishing_material() -> None:
    primary = derive_primary_key()
    secondary = derive_secondary_key()
    assert len(primary) == 20
    assert len(secondary) == 20
    assert hashlib.sha256(primary).hexdigest() == (
        "a94195fde3de5eb2f1814139f83ecc9a51864dee4fb722c625d18ce1971054c0"
    )
    assert hashlib.sha256(secondary).hexdigest() == (
        "b2aeddd9f0d8de5cd43fb3baab30dc99ddd9dfb0347c12ed95674307f2335f62"
    )


def test_xloader_decrypt_known_vector() -> None:
    result = xloader_decrypt(bytes(range(64)), derive_primary_key())
    assert hashlib.sha256(result).hexdigest() == (
        "b3efe9ed11f71059743670761a9b03fa155c6812d13d90f0dfcba662dbe0aadb"
    )


def test_find_unique_marker_rejects_missing_and_duplicate() -> None:
    with pytest.raises(InjectedStubError, match="見つかりません"):
        find_unique_marker(b"A" * 32, FIRST_MARKER)
    marker = struct.pack("<I", FIRST_MARKER)
    with pytest.raises(InjectedStubError, match="複数"):
        find_unique_marker(marker + b"A" + marker, FIRST_MARKER)


def test_recover_stub_rejects_reversed_boundaries() -> None:
    image = struct.pack("<I", SECOND_MARKER) + b"A" * 8 + struct.pack(
        "<I", FIRST_MARKER
    )
    with pytest.raises(InjectedStubError, match="境界順序"):
        recover_stub(image)


def test_module_relative_calls_uses_original_module_rva() -> None:
    # RVA 0x1000 に置いた E8 +5 は、次命令 0x1005 から 0x100A を指す。
    calls = module_relative_calls(b"\xe8\x05\x00\x00\x00\xc3", 0x1000)
    assert calls == [{"source_rva": "0x1000", "target_rva": "0x100a"}]


def test_x86_score_distinguishes_valid_straight_line_code() -> None:
    score = x86_score(b"\x55\x8b\xec\x90\x5d\xc3")
    assert score["decoded_ratio"] == 1.0
    assert score["entry_mnemonics"][:3] == ["push", "mov", "nop"]
