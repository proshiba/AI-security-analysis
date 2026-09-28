"""tiny人工XORだけで切断prefixの非採用と明示終端の互換を検証する。"""

from __future__ import annotations

import itertools

import pytest

from extractors.vidar import extractor

KEY = b"0123456789abcdef"
URL = b"https://example.test/gate"


def _blob(records=None, *, count=1, build=b"fixture"):
    """固定offsetへ人工値と明示空recordを置き、最大33件だけを作る。"""
    if records is None:
        records = [(URL, b"tag", b"FixtureAgent/1")] * count
    assert len(records) <= 33
    blob = bytearray(0x072 + 0x243 * (len(records) + (len(records) <= 32)))
    blob[:16] = KEY

    def store(base, value_offset, length_offset, value):
        blob[base + length_offset] = len(value)
        blob[base + value_offset:base + value_offset + len(value)] = bytes(left ^ right for left, right in zip(value, itertools.cycle(KEY)))

    store(0, 0x010, 0x030, b"1.8")
    store(0, 0x031, 0x071, build)
    for index, (url, tag, agent) in enumerate(records):
        base = 0x072 + index * 0x243
        store(base, 0, 0x100, url)
        store(base, 0x101, 0x141, tag)
        store(base, 0x142, 0x242, agent)
    return bytes(blob)


def _assert_rejected(data):
    """内部候補と公開回収の双方で不完全設定が採用されないことを確認する。"""
    assert extractor._try_config(data, 0) is None
    assert extractor.recover_xor_config(data) == {}
    result = extractor.extract(data, "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["xor_config_assessment"]["valid_candidate_count"] == 0


@pytest.mark.parametrize("count", [1, 2, 31, 32])
def test_explicit_empty_url_terminal_preserves_maximum_records(count):
    recovered = extractor.recover_xor_config(_blob(count=count))
    assert len(recovered["records"]) == count
    assert recovered["records"] == [{"url": URL.decode(), "tag": "tag", "user_agent": "FixtureAgent/1"}] * count
    assert extractor.MAX_RECORDS == 32


@pytest.mark.parametrize("count", [1, 2, 31, 32])
def test_missing_next_url_length_is_not_an_empty_terminal(count):
    data = _blob(count=count)
    _assert_rejected(data[:0x072 + count * 0x243 + 0x100])


@pytest.mark.parametrize("tail", [b"ftp://example.test/path", b"https://example.test/\x01", b"https://example.test/\xff"])
def test_invalid_later_url_does_not_select_valid_prefix(tail):
    _assert_rejected(_blob(records=[(URL, b"tag", b"FixtureAgent/1"), (tail, b"tag", b"FixtureAgent/1")]))


@pytest.mark.parametrize("marker", [0x141, 0x242])
def test_missing_later_tag_or_agent_length_rejects_candidate(marker):
    data = _blob(count=2)
    _assert_rejected(data[:0x072 + 0x243 + marker])


@pytest.mark.parametrize("marker", [0x141, 0x242])
def test_recognized_first_record_truncation_has_incomplete_assessment(marker):
    data = _blob()[:0x072 + marker]
    recovered, incomplete = extractor._try_config_assessment(data, 0)
    assert recovered is None
    assert incomplete is True
    assessment = extractor.extract(data, "synthetic.bin")["config"]["xor_config_assessment"]
    assert assessment["reason"] == "incomplete_record_profile"
    assert assessment["scan_complete"] is False


def test_later_tag_payload_past_input_is_not_empty_tag():
    data = bytearray(_blob(count=2))
    base = 0x072 + 0x243
    data[base + 0x141] = 255
    _assert_rejected(bytes(data[:base + 0x141 + 1]))


@pytest.mark.parametrize("tail", [URL, b"ftp://example.test/path", b"https://example.test/\xff"])
def test_nonempty_record_33_is_not_silently_ignored(tail):
    records = [(URL, b"tag", b"FixtureAgent/1")] * 32 + [(tail, b"tag", b"FixtureAgent/1")]
    _assert_rejected(_blob(records=records))


def test_record_33_payload_is_not_decrypted(monkeypatch):
    original = extractor._try_config.__globals__["_decrypt_field"]
    calls = []

    def tracked(data, base, value_offset, length_offset, key):
        calls.append((base, value_offset, length_offset))
        return original(data, base, value_offset, length_offset, key)

    monkeypatch.setitem(extractor._try_config.__globals__, "_decrypt_field", tracked)
    assert extractor._try_config(_blob(count=33), 0) is None
    assert all(base < 0x072 + 32 * 0x243 for base, _value, _length in calls)


@pytest.mark.parametrize("count", [1, 32])
def test_terminal_requires_only_available_zero_url_length(count):
    data = _blob(count=count)
    marker = 0x072 + count * 0x243 + 0x100
    recovered = extractor._try_config(data[:marker + 1], 0)
    assert len(recovered["records"]) == count


def test_zero_length_build_tag_and_agent_are_valid_empty_values():
    recovered = extractor.recover_xor_config(_blob(records=[(URL, b"", b"")], build=b""))
    assert recovered["build_id"] == ""
    assert recovered["records"] == [{"url": URL.decode(), "tag": "", "user_agent": ""}]


@pytest.mark.parametrize("field", ["build", "tag", "agent"])
def test_none_field_is_never_promoted_to_empty_value(monkeypatch, field):
    original = extractor._try_config.__globals__["_decrypt_field"]
    offsets = {"build": (0, 0x031, 0x071), "tag": (0x072, 0x101, 0x141), "agent": (0x072, 0x142, 0x242)}

    def truncated(data, base, value_offset, length_offset, key):
        if (base, value_offset, length_offset) == offsets[field]:
            return None
        return original(data, base, value_offset, length_offset, key)

    monkeypatch.setitem(extractor._try_config.__globals__, "_decrypt_field", truncated)
    assert extractor._try_config(_blob(), 0) is None


@pytest.mark.parametrize("value_offset,length_offset", [(0x031, 0x071), (0x101, 0x141), (0x142, 0x242)])
def test_field_missing_length_byte_returns_none(value_offset, length_offset):
    assert extractor._decrypt_field(bytes(length_offset), 0, value_offset, length_offset, KEY) is None


@pytest.mark.parametrize("value_offset,length_offset", [(50, 40), (257, 321), (600, 578)])
def test_field_payload_past_input_returns_none(value_offset, length_offset):
    data = bytearray(length_offset + 1)
    data[length_offset] = 255
    assert extractor._decrypt_field(bytes(data), 0, value_offset, length_offset, KEY) is None


@pytest.mark.parametrize("url,role", [(b"https://example.test/path", "c2_or_bootstrap_candidate"), (b"https://telegram.me/fixture_profile", "dead_drop.telegram")])
def test_complete_profile_keeps_candidate_and_dead_drop_roles(url, role):
    result = extractor.extract(_blob(records=[(url, b"tag", b"FixtureAgent/1")]), "synthetic.bin")
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["endpoint_semantics"][0]["role"] == role
    assert result["config"]["final_c2_recovered"] is False
    assert all(item["confidence"] != "confirmed" for item in result["findings"])


@pytest.mark.parametrize("partial_kind,partial_first", [
    ("url_marker_missing", False), ("url_marker_missing", True),
    ("tag_marker_missing", False), ("agent_marker_missing", False),
    ("record_33", False), ("record_33", True),
    ("later_invalid_url", False), ("later_invalid_url", True),
])
def test_recognized_partial_candidate_blocks_whole_view_selection(partial_kind, partial_first):
    complete = _blob(build=b"complete")
    if partial_kind == "record_33":
        partial = _blob(count=33, build=b"partial")
    elif partial_kind == "later_invalid_url":
        partial = _blob(records=[(URL, b"tag", b"FixtureAgent/1"), (b"ftp://example.test/path", b"tag", b"FixtureAgent/1")], build=b"partial")
    elif partial_kind == "url_marker_missing":
        partial = _blob(count=32, build=b"partial")[:0x072 + 32 * 0x243 + 0x100]
    else:
        marker = {"tag_marker_missing": 0x141, "agent_marker_missing": 0x242}[partial_kind]
        partial = _blob(count=2, build=b"partial")[:0x072 + 0x243 + marker]
    data = partial + complete if partial_first else complete + partial
    assert extractor.recover_xor_config(data) == {}
    result = extractor.extract(data, "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assessment = result["config"]["xor_config_assessment"]
    assert assessment["reason"] == "incomplete_record_profile"
    assert assessment["scan_complete"] is False
    assert assessment["status"] == "not_recovered"
    assert "records" not in result["config"]
    assert "xor_key_sha256" not in result["config"]
    assert "partial" not in repr(assessment)


@pytest.mark.parametrize("invalid", [b"not-profile", bytes(400)])
def test_nonprofile_input_does_not_block_complete_selection(invalid):
    result = extractor.recover_xor_config(invalid + _blob())
    assert result["config_offset"] == len(invalid)
