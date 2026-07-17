"""Unit tests for every public StealC extractor function."""

from __future__ import annotations

import base64

from extractors.stealc.extractor import DecodedProfile, extract, extract_rc4_profile, extract_xor_profile, rc4_skip


def _standard_rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for index in range(256):
        j = (j + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[j] = state[j], state[index]
    output = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def test_rc4_skip_and_empty_key() -> None:
    key = b"92082364821226974234"
    encrypted = _standard_rc4(b"http://example.test", key)
    assert rc4_skip(encrypted, key) == b"http://example.test"
    try:
        rc4_skip(b"x", b"")
    except ValueError:
        pass
    else:
        raise AssertionError("empty keys must fail")


def test_decoded_profile_urls() -> None:
    profile = DecodedProfile("fixture", "http://example.test", "/gate.php", "/dll/", "A", 99)
    assert profile.c2_url == "http://example.test/gate.php"
    assert profile.dll_url == "http://example.test/dll/"


def test_public_extractors_reject_non_pe() -> None:
    assert extract_rc4_profile(b"not-a-pe") is None
    assert extract_xor_profile(b"not-a-pe") is None
    result = extract(b"not-a-pe", "fixture.bin")
    assert result["family"] == "stealc"
    assert result["config"]["profile"] is None
    assert result["executed"] is False and result["network_contacted"] is False
