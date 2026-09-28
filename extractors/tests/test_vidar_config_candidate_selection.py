"""人工XOR bytesだけで既存Vidar候補の一意選択と非昇格を検証する。"""

from __future__ import annotations

import hashlib
import itertools

import pytest

from extractors.vidar import extractor

URL = b"https://example.test/gate"
DEFAULT_RECORDS = ((URL, b"tag", b"FixtureAgent/1"),)


def _blob(*, version=b"1.8", build=b"fixture", records=DEFAULT_RECORDS, key=b"0123456789abcdef") -> bytes:
    """既存offsetの設定と明示的な空record終端を人工生成する。"""
    blob = bytearray(0x072 + 0x243 * (len(records) + 1))
    blob[:16] = key

    def store(base, value_offset, length_offset, value):
        blob[base + length_offset] = len(value)
        encoded = bytes(left ^ right for left, right in zip(value, itertools.cycle(key)))
        blob[base + value_offset : base + value_offset + len(value)] = encoded

    store(0, 0x010, 0x030, version)
    store(0, 0x031, 0x071, build)
    for index, (url, tag, agent) in enumerate(records):
        base = 0x072 + index * 0x243
        store(base, 0, 0x100, url)
        store(base, 0x101, 0x141, tag)
        store(base, 0x142, 0x242, agent)
    return bytes(blob)


def _assessment(data: bytes) -> dict:
    """公開値を使わず、固定code／件数の診断だけを取得する。"""
    return extractor.extract(data, "synthetic.bin")["config"]["xor_config_assessment"]


def test_single_profile_preserves_every_existing_recovery_field():
    data = _blob()
    assert extractor.recover_xor_config(data) == {
        "version": "1.8",
        "build_id": "fixture",
        "records": [{"url": URL.decode(), "tag": "tag", "user_agent": "FixtureAgent/1"}],
        "c2_urls": [URL.decode()],
        "xor_key_sha256": hashlib.sha256(b"0123456789abcdef").hexdigest(),
        "profile": "vidar_repeated_xor_v1_5_plus",
        "config_offset": 0,
        "scan_source": "complete_input",
        "original_size": len(data),
    }
    assert _assessment(data) == {
        "schema_version": 1, "status": "recovered", "reason": "unique_profile",
        "scan_source": "complete_input", "scan_complete": True,
        "identity_unique": True,
        "candidate_attempts": 1, "valid_candidate_count": 1, "distinct_profile_count": 1,
    }


@pytest.mark.parametrize("prefix", [b"", b"MZ ordinary prefix\0", bytes(1024)])
def test_equivalent_duplicates_keep_first_offset(prefix):
    record = _blob()
    data = prefix + record + bytes(47) + record
    recovered = extractor.recover_xor_config(data)
    assert recovered["config_offset"] == len(prefix)
    assert recovered["original_size"] == len(data)
    assert recovered["records"] == [{"url": URL.decode(), "tag": "tag", "user_agent": "FixtureAgent/1"}]
    assert _assessment(data)["valid_candidate_count"] == 2
    assert _assessment(data)["distinct_profile_count"] == 1


@pytest.mark.parametrize("other", [
    {"version": b"1.9"},
    {"build": b"other"},
    {"records": ((b"https://other.test/gate", b"tag", b"FixtureAgent/1"),)},
    {"records": ((URL, b"other", b"FixtureAgent/1"),)},
    {"records": ((URL, b"tag", b"OtherAgent/1"),)},
    {"records": ((URL, b"tag", b"FixtureAgent/1"), (URL, b"tag", b"FixtureAgent/1"))},
    {"key": b"fedcba9876543210"},
])
def test_all_profile_fields_participate_in_conflict_identity(other):
    data = _blob() + bytes(47) + _blob(**other)
    assert extractor.recover_xor_config(data) == {}
    result = extractor.extract(data, "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assessment = result["config"]["xor_config_assessment"]
    assert assessment["reason"] == "conflicting_profiles"
    assert assessment["scan_complete"] is True
    assert assessment["identity_unique"] is False
    assert assessment["valid_candidate_count"] == 2
    assert assessment["distinct_profile_count"] == 2
    assert "records" not in result["config"]
    assert "xor_key_sha256" not in result["config"]


def test_record_order_is_not_canonicalized_away():
    records = ((URL, b"tag", b"FixtureAgent/1"), (b"https://other.test/path", b"other", b"OtherAgent/1"))
    data = _blob(records=records) + bytes(47) + _blob(records=records[::-1])
    assert extractor.recover_xor_config(data) == {}
    assert _assessment(data)["reason"] == "conflicting_profiles"


@pytest.mark.parametrize("invalid", [
    {"version": b"abc"},
    {"version": b""},
    {"build": b"\x01"},
    {"records": ((URL, b"\x01", b"FixtureAgent/1"),)},
    {"records": ((URL, b"tag", b"\x01"),)},
])
def test_existing_grammar_rejections_do_not_override_later_valid_profile(invalid):
    malformed = _blob(**invalid)
    valid = _blob()
    data = malformed + bytes(47) + valid
    recovered = extractor.recover_xor_config(data)
    assert recovered["config_offset"] == len(malformed) + 47
    assert recovered["records"][0]["url"] == URL.decode()
    assert _assessment(data)["valid_candidate_count"] == 1


@pytest.mark.parametrize("count", [1, 2, 63, 64])
def test_candidate_budget_boundary_accepts_complete_equivalent_set(count):
    data = (_blob() + bytes(47)) * count
    assert extractor.recover_xor_config(data)["config_offset"] == 0
    assessment = _assessment(data)
    assert assessment["candidate_attempts"] == count
    assert assessment["valid_candidate_count"] == count
    assert assessment["scan_complete"] is True
    assert assessment["identity_unique"] is True


@pytest.mark.parametrize("tail", [_blob(), _blob(build=b"other")])
def test_candidate_65_is_not_silently_omitted(tail):
    data = (_blob() + bytes(47)) * 64 + tail
    assert extractor.recover_xor_config(data) == {}
    assessment = _assessment(data)
    assert assessment["reason"] == "candidate_limit_exceeded"
    assert assessment["candidate_attempts"] == 64
    assert assessment["valid_candidate_count"] == 64
    assert assessment["scan_complete"] is False
    assert assessment["identity_unique"] is None


def test_invalid_candidates_also_consume_attempt_budget():
    data = (_blob(version=b"abc") + bytes(47)) * 64 + _blob()
    assert extractor.recover_xor_config(data) == {}
    assessment = _assessment(data)
    assert assessment["reason"] == "candidate_limit_exceeded"
    assert assessment["valid_candidate_count"] == 0


def test_length_markers_without_http_prefilter_do_not_consume_parse_budget():
    data = bytes([3]) * 4096 + _blob()
    assert extractor.recover_xor_config(data)["config_offset"] == 4096
    assert _assessment(data)["candidate_attempts"] == 1


def test_incomplete_prefix_does_not_assert_static_recovery(monkeypatch):
    record = _blob()
    data = record + bytes(1024)
    monkeypatch.setattr(extractor, "MAX_CONFIG_SCAN", len(record))
    assert extractor.recover_xor_config(data) == {}
    result = extractor.extract(data, "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assessment = result["config"]["xor_config_assessment"]
    assert assessment["reason"] == "input_view_incomplete"
    assert assessment["scan_source"] == "bounded_prefix"
    assert assessment["candidate_attempts"] == 0
    assert assessment["scan_complete"] is False
    assert assessment["identity_unique"] is None


def test_complete_compacted_view_uses_independent_hard_bound(monkeypatch):
    compact = _blob()
    data = b"MZ" + bytes(2048)
    monkeypatch.setattr(extractor, "MAX_CONFIG_SCAN", 1024)
    monkeypatch.setattr(extractor, "recover_inflated_pe", lambda _data: ({"status": "recovered"}, compact))
    assert extractor.recover_xor_config(data)["scan_source"] == "inflated_pe_compacted"
    assert _assessment(data)["scan_complete"] is True


def test_oversized_compacted_view_is_not_selected(monkeypatch):
    compact = _blob()
    data = b"MZ" + bytes(2048)
    monkeypatch.setattr(extractor, "MAX_CONFIG_SCAN", 1024)
    monkeypatch.setattr(extractor, "MAX_CONFIG_VIEW_BYTES", len(compact) - 1)
    monkeypatch.setattr(extractor, "recover_inflated_pe", lambda _data: ({"status": "recovered"}, compact))
    assert extractor.recover_xor_config(data) == {}
    assert _assessment(data)["reason"] == "input_view_incomplete"


@pytest.mark.parametrize("compact", [None, bytearray(b"unknown"), {"unknown": "profile"}])
def test_unknown_compacted_output_is_not_a_recovery_view(monkeypatch, compact):
    data = b"MZ" + bytes(2048)
    monkeypatch.setattr(extractor, "MAX_CONFIG_SCAN", 1024)
    monkeypatch.setattr(extractor, "recover_inflated_pe", lambda _data: ({}, compact))
    assert extractor.recover_xor_config(data) == {}
    assert _assessment(data)["scan_complete"] is False


@pytest.mark.parametrize("data,reason", [(b"", "input_too_short"), (bytes(1200), "no_valid_profile")])
def test_empty_or_unknown_input_remains_unrecovered(data, reason):
    assert extractor.recover_xor_config(data) == {}
    assessment = _assessment(data)
    assert assessment["reason"] == reason
    assert assessment["status"] == "not_recovered"
    assert assessment["scan_complete"] is True


@pytest.mark.parametrize("url,role", [
    (b"https://example.test/full/path?fixture=1", "c2_or_bootstrap_candidate"),
    (b"https://telegram.me/fixture_profile", "dead_drop.telegram"),
    (b"https://www.pinterest.com/fixture_profile", "dead_drop.pinterest_profile"),
    (b"https://steamcommunity.com/profiles/76561198000000000", "dead_drop.steam_profile"),
])
def test_success_keeps_endpoint_roles_and_final_c2_unresolved(url, role):
    result = extractor.extract(_blob(records=((url, b"tag", b"FixtureAgent/1"),)), "synthetic.bin")
    config = result["config"]
    assert config["static_config_recovered"] is True
    assert config["final_c2_recovered"] is False
    assert config["endpoint_semantics"][0]["role"] == role
    assert all(item["confidence"] != "confirmed" for item in result["findings"])
    assert "confirmed_c2" not in config


def test_assessment_contains_only_fixed_codes_flags_and_counts():
    assessment = _assessment(_blob() + _blob(build=b"secret-build-value"))
    assert set(assessment) == {"schema_version", "status", "reason", "scan_source", "scan_complete", "identity_unique", "candidate_attempts", "valid_candidate_count", "distinct_profile_count"}
    assert assessment["reason"] == "conflicting_profiles"
    assert all(value is None or type(value) in {str, int, bool} for value in assessment.values())
    assert "secret-build-value" not in repr(assessment)
    assert URL.decode() not in repr(assessment)
    assert "0123456789abcdef" not in repr(assessment)


def test_conflict_is_distinct_from_truncation_and_scan_finishes():
    data = _blob() + _blob(build=b"other") + _blob()
    assert extractor.recover_xor_config(data) == {}
    assessment = _assessment(data)
    assert assessment["reason"] == "conflicting_profiles"
    assert assessment["scan_complete"] is True
    assert assessment["identity_unique"] is False
    assert assessment["candidate_attempts"] == 3
    assert assessment["valid_candidate_count"] == 3
    assert assessment["distinct_profile_count"] == 2


def test_truncation_retains_already_proven_conflict_without_success():
    data = _blob() + _blob(build=b"other") + (_blob() + bytes(47)) * 63
    assert extractor.recover_xor_config(data) == {}
    assessment = _assessment(data)
    assert assessment["reason"] == "candidate_limit_exceeded"
    assert assessment["scan_complete"] is False
    assert assessment["identity_unique"] is False
    assert assessment["status"] == "not_recovered"
    assert assessment["candidate_attempts"] == 64
    assert assessment["distinct_profile_count"] == 2
