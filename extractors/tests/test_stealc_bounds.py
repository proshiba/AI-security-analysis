"""Tests for deterministic StealC RC4 candidate budgets."""

from __future__ import annotations

from extractors.stealc import extractor


def test_base64_candidates_are_unique_and_bounded(monkeypatch) -> None:
    """Reject oversized values and stop at the configured unique-value cap."""
    monkeypatch.setattr(extractor, "MAX_ENCODED_VALUES", 2)
    monkeypatch.setattr(extractor, "MAX_ENCODED_LENGTH", 12)
    values = [b"QUJDRA==", b"QUJDRA==", b"RUZHSA==", b"SUpLTE1OT1BR"]
    assert extractor._base64_candidates(values) == [b"QUJDRA==", b"RUZHSA=="]


def test_key_candidates_and_even_sample_have_hard_limits(monkeypatch) -> None:
    """Bound key breadth and retain both ends of a deterministic probe sample."""
    monkeypatch.setattr(extractor, "MAX_KEY_CANDIDATES", 2)
    keys = [b"1" * 20, b"2" * 20, b"3" * 20, b"1" * 20]
    assert extractor._key_candidates(keys) == keys[:2]
    values = [str(index).encode().ljust(8, b"A") for index in range(10)]
    sampled = extractor._even_sample(values, 4)
    assert len(sampled) == 4
    assert sampled[0] == values[0]
    assert sampled[-1] == values[-1]


def test_rc4_profile_ranks_keys_before_full_decode(monkeypatch) -> None:
    """Fully decode only the bounded best probe keys while preserving a profile."""
    good_key = b"7" * 20
    other_keys = [bytes(str(index), "ascii") * 20 for index in range(1, 7)]
    encoded = [b"QUJDRA=="] * 80
    monkeypatch.setattr(extractor, "_pe", lambda _data: object())
    monkeypatch.setattr(
        extractor,
        "_candidate_strings",
        lambda _data, _image: [good_key, *other_keys, *encoded],
    )
    monkeypatch.setattr(extractor, "_base64_candidates", lambda _values: encoded)
    calls: list[tuple[bytes, int]] = []

    def decode(values: list[bytes], key: bytes) -> tuple[int, list[str]]:
        calls.append((key, len(values)))
        if len(values) <= extractor.MAX_PROBE_VALUES:
            return (50 if key == good_key else 0), []
        strings = ["http://example.test", "/gate.php", "/dlls/", "fixture"] + ["value"] * 56
        return (200 if key == good_key else 0), (strings if key == good_key else [])

    monkeypatch.setattr(extractor, "_decode_base64_values", decode)
    profile = extractor.extract_rc4_profile(b"MZ")
    full_calls = [item for item in calls if item[1] == len(encoded)]
    assert profile is not None and profile.c2_url == "http://example.test/gate.php"
    assert len(full_calls) == extractor.MAX_FINAL_KEYS
