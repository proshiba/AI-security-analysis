"""Pureの未評価nested messageと固定探索予算を人工protobufだけで検証する。"""

from __future__ import annotations

import base64
import gzip

import pytest

from extractors.purehvnc import extractor


def _varint(value: int) -> bytes:
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _field(number: int, value: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _config(host: bytes = b"leaf.example") -> bytes:
    return _field(1, host) + _varint(16) + _varint(443)


def _wrapped(value: bytes, depth: int) -> bytes:
    for _ in range(depth):
        value = _field(17, value)
    return value


def _encoded(value: bytes) -> str:
    return base64.b64encode(gzip.compress(value, mtime=0)).decode("ascii")


@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_supported_depth_with_plaintext_leaf_still_recovers(depth: int) -> None:
    """上限ちょうど3のhost・証明書風plaintextはnested構造ではなく正常leaf。"""
    message = _config() + _field(3, b"certificate-plaintext-leaf")
    raw, fields = extractor.decode_config_blob([_encoded(_wrapped(message, depth))])
    assert raw == message
    assert fields[1] == [b"leaf.example"]
    assert fields[2] == [443]


@pytest.mark.parametrize("first", [True, False])
def test_depth_four_conflict_in_same_message_rejects_in_both_field_orders(first: bool) -> None:
    """上限前の設定を見つけても、後方の未評価候補を捨てて成功しない。"""
    top = _config(b"first.example")
    buried = _field(38, _wrapped(_config(b"other.example"), 3))
    clear = top + buried if first else buried + top
    with pytest.raises(ValueError, match="nested message depth limit exceeded"):
        extractor.decode_config_blob([_encoded(clear)])


@pytest.mark.parametrize("first", [True, False])
def test_depth_four_after_other_encoded_candidate_rejects_in_both_orders(first: bool) -> None:
    values = [_encoded(_config()), _encoded(_wrapped(_config(b"other.example"), 4))]
    if not first:
        values.reverse()
    with pytest.raises(ValueError, match="nested message depth limit exceeded"):
        extractor.decode_config_blob(values)


@pytest.mark.parametrize("leaf", [_config(), b"\x08\x01"])
def test_depth_four_valid_structure_rejects_even_without_config(leaf: bytes) -> None:
    """設定schemaに一致しないmessageでも、構造走査の不完全性を消さない。"""
    with pytest.raises(ValueError, match="nested message depth limit exceeded"):
        extractor.decode_config_blob([_encoded(_wrapped(leaf, 4))])


@pytest.mark.parametrize("depth", [0, 1, 2])
def test_plaintext_that_is_also_valid_protobuf_remains_supported_before_boundary(depth: int) -> None:
    """schema無し構造判定と競合しない浅いIPv4設定の旧結果を保持する。"""
    raw, fields = extractor.decode_config_blob([_encoded(_wrapped(_config(b"192.0.2.1"), depth))])
    assert raw == _config(b"192.0.2.1")
    assert fields[1] == [b"192.0.2.1"]


def test_plaintext_that_is_also_valid_protobuf_is_conservatively_incomplete_at_depth_three() -> None:
    """9-byte IPv4文字列はfixed64 protobufでもあるため上限先では保守的拒否。"""
    assert extractor.parse_protobuf(b"192.0.2.1") == {6: [b"92.0.2.1"]}
    with pytest.raises(ValueError, match="nested message depth limit exceeded"):
        extractor.decode_config_blob([_encoded(_wrapped(_config(b"192.0.2.1"), 3))])


def test_depth_three_conflict_remains_conflict_not_incomplete() -> None:
    clear = _config(b"first.example") + _field(38, _wrapped(_config(b"other.example"), 2))
    with pytest.raises(ValueError, match="conflicting managed PureRAT"):
        extractor.decode_config_blob([_encoded(clear)])


def test_depth_four_structure_is_not_normalized_or_yielded(monkeypatch: pytest.MonkeyPatch) -> None:
    """上限先は構造確認のみで、設定判定へ渡さない。"""
    original = extractor._normalise_config_fields
    normalized = []

    def record(fields):
        normalized.append(fields)
        return original(fields)

    monkeypatch.setattr(extractor, "_normalise_config_fields", record)
    with pytest.raises(ValueError, match="depth limit exceeded"):
        list(extractor._iter_nested_messages(_wrapped(_config(), 4)))
    assert len(normalized) == 4
    assert all(1 not in fields for fields in normalized)


@pytest.mark.parametrize("invalid", [False, True])
def test_exact_128_unique_parse_attempts_then_reject_before_129th(
    invalid: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """失敗するleafも課金し、129番目のparser呼出しより先に拒否する。"""
    assert extractor.MAX_CONFIG_MESSAGE_CANDIDATES == 128
    original = extractor.parse_protobuf
    visits = []

    def record(raw):
        visits.append(raw)
        return original(raw)

    monkeypatch.setattr(extractor, "parse_protobuf", record)
    children = [bytes((15, index)) if invalid else b"\x08" + _varint(index) for index in range(1, 129)]
    exact = b"".join(_field(17, child) for child in children[:127])
    list(extractor._iter_nested_messages(exact))
    assert len(visits) == 128
    assert len(set(visits)) == 128
    visits.clear()
    over = b"".join(_field(17, child) for child in children)
    with pytest.raises(ValueError, match="nested message candidate limit exceeded"):
        list(extractor._iter_nested_messages(over))
    assert len(visits) == 128
    assert children[-1] not in visits


def test_duplicate_raw_is_not_charged_or_parsed_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    original = extractor.parse_protobuf
    visits = []

    def record(raw):
        visits.append(raw)
        return original(raw)

    monkeypatch.setattr(extractor, "parse_protobuf", record)
    repeated = b"".join(_field(17, b"\x08\x01") for _ in range(128))
    assert len(list(extractor._iter_nested_messages(repeated))) == 2
    assert len(visits) == len(set(visits)) == 2


def test_depth_four_duplicate_already_examined_at_shallower_depth_is_not_incomplete() -> None:
    """同じrawの内容を浅い位置で評価済みなら、深いaliasへ再課金しない。"""
    config = _config()
    clear = _field(19, config) + _field(38, _wrapped(config, 3))
    raw, fields = extractor.decode_config_blob([_encoded(clear)])
    assert raw == config
    assert fields[1] == [b"leaf.example"]


def test_unique_invalid_leaf_budget_does_not_return_earlier_config(monkeypatch: pytest.MonkeyPatch) -> None:
    clear = _config() + b"".join(_field(17, bytes((15, index))) for index in range(1, 129))
    with pytest.raises(ValueError, match="nested message candidate limit exceeded"):
        extractor.decode_config_blob([_encoded(clear)])


def test_managed_config_boundary_does_not_restore_incomplete_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """人工文字列reader境界からも不完全走査を設定成功へ戻さない。"""
    value = _encoded(_config() + _field(38, _wrapped(_config(b"other.example"), 3)))
    monkeypatch.setattr(extractor, "iter_dotnet_user_strings", lambda _data: iter((value,)))
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: False)
    with pytest.raises(ValueError, match="depth limit exceeded"):
        extractor.extract_managed_config(b"synthetic-reader-boundary")


@pytest.mark.parametrize("native_candidate", [False, True])
def test_non_chrd_normal_extract_does_not_confirm_incomplete_managed_config(
    native_candidate: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """別native候補を残しても、同一managed走査の失敗を確定C2へ戻さない。"""
    value = _encoded(_config() + _field(38, _wrapped(_config(b"other.example"), 3)))
    monkeypatch.setattr(extractor, "iter_dotnet_user_strings", lambda _data: iter((value,)))
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: False)

    def native(_data):
        if not native_candidate:
            raise ValueError("synthetic native profile is absent")
        return {"variant": "native_10fx", "endpoints": ["192.0.2.1:443"]}

    monkeypatch.setattr(extractor, "extract_native_config", native)
    result = extractor.extract(b"synthetic-non-chrd-reader", "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["decoded_config_recovered"] is False
    assert result["c2"] == []
    assert result["executed"] is False
    assert result["network_contacted"] is False
    assert result["credentials_published"] is False
    if native_candidate:
        assert result["config"]["variant"] == "native_10fx"
        assert [item["confidence"] for item in result["findings"]] == ["high"]
    else:
        assert result["config"]["variant"] == "unrecognized"
        assert result["findings"] == []


def test_fixed_limits_unchanged() -> None:
    assert extractor.MAX_CONFIG_NESTING == 3
    assert extractor.MAX_CONFIG_MESSAGE_CANDIDATES == 128
    assert extractor.MAX_CONFIG_CLEAR_BYTES == 4 * 1024 * 1024
    assert extractor.MAX_CONFIG_PROTOBUF_FIELDS == 4096
    assert extractor.MAX_CONFIG_DECODE_CANDIDATES == 64


def test_clear_byte_limit_remains_downscaled_exact_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """小さい人工fixtureで元4MiB上限の同じ境界条件を試す。"""
    monkeypatch.setattr(extractor, "MAX_CONFIG_CLEAR_BYTES", 8)
    assert extractor._bounded_gzip_decompress(gzip.compress(bytes(8), mtime=0)) == bytes(8)
    with pytest.raises(ValueError, match="output boundaries"):
        extractor._bounded_gzip_decompress(gzip.compress(bytes(9), mtime=0))
    with pytest.raises(ValueError, match="input exceeds"):
        extractor.parse_protobuf(bytes(9))


def test_field_budget_4096_boundary_still_fail_closed() -> None:
    assert extractor.parse_protobuf(b"\x08\x01" * 4096) == {1: [1] * 4096}
    with pytest.raises(ValueError, match="field count exceeds"):
        extractor.parse_protobuf(b"\x08\x01" * 4097)


def test_encoded_candidate_64_budget_cannot_be_bypassed_by_duplicates() -> None:
    value = _encoded(_config())
    assert extractor.decode_config_blob([value] * 64)[1][1] == [b"leaf.example"]
    with pytest.raises(ValueError, match="Base64/GZip candidate limit exceeded"):
        extractor.decode_config_blob([value] * 65)
