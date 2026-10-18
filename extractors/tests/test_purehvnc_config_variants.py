"""PureRAT managed configの版差と安全境界を検証する。"""

from __future__ import annotations

import base64
import gzip
import hashlib
import os
from pathlib import Path

import pytest

from extractors.purehvnc import extractor


def _varint(value: int) -> bytes:
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _bytes_field(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def _varint_field(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def _fixed32_field(number: int, value: bytes) -> bytes:
    assert len(value) == 4
    return _varint((number << 3) | 5) + value


def _fixed64_field(number: int, value: bytes) -> bytes:
    assert len(value) == 8
    return _varint((number << 3) | 1) + value


def _gzip_base64(value: bytes) -> str:
    return base64.b64encode(gzip.compress(value, mtime=0)).decode("ascii")


def _v4_default_elided_field_7_message() -> bytes:
    """9f201e04…で確認したfield inventoryと同形の合成設定を返す。"""

    return b"".join(
        (
            _bytes_field(1, b"elided.example.test"),
            _varint_field(2, 56001),
            _varint_field(2, 56002),
            _varint_field(2, 56003),
            _bytes_field(3, b"fixture-pfx"),
            _bytes_field(4, b"Default"),
            _varint_field(5, 1),
            _varint_field(6, 0),
            # field 7は空文字のprotobuf既定値としてwire上から省略される。
            _bytes_field(8, b"APPDATA"),
            _bytes_field(9, b"purecrack-default"),
            _varint_field(10, 1),
        )
    )


def test_v4_field_7_default_elision_gets_a_distinct_schema_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """field 7省略を受理するが、旧1～9明示flagの意味は変更しない。"""

    encoded = _gzip_base64(_v4_default_elided_field_7_message())
    monkeypatch.setattr(
        extractor,
        "iter_dotnet_user_strings",
        lambda _data: iter((encoded, "4.4.1")),
    )
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: False)
    monkeypatch.setattr(
        extractor,
        "certificate_metadata",
        lambda _value: {"pfx_sha256": "a" * 64},
    )

    config = extractor.extract_managed_config(b"MZ managed fixture")

    assert config["protobuf_fields_1_to_9_valid"] is False
    assert config["protobuf_terminal_schema_valid"] is True
    assert config["protobuf_terminal_schema_profile"] == (
        extractor.TERMINAL_SCHEMA_PROFILE_V4_DEFAULT_ELIDED_FIELD_7
    )
    assert config["protobuf_field_numbers"] == [1, 2, 3, 4, 5, 6, 8, 9, 10]
    assert config["protobuf_default_elided_fields"] == [7]
    assert config["endpoints"] == [
        "elided.example.test:56001",
        "elided.example.test:56002",
        "elided.example.test:56003",
    ]


PRIVATE_FIELD_7_ELIDED_SAMPLE = "PURERAT_FIELD7_ELIDED_TEST_IMAGE"


@pytest.mark.skipif(
    not os.environ.get(PRIVATE_FIELD_7_ELIDED_SAMPLE),
    reason="repo外のPureRAT field 7省略実検体が未指定です",
)
def test_private_real_field_7_elided_terminal_remains_static_positive() -> None:
    """実終端PEを実行・通信せず既知v4 schemaとして復元する。"""

    sample = Path(os.environ[PRIVATE_FIELD_7_ELIDED_SAMPLE]).read_bytes()
    assert hashlib.sha256(sample).hexdigest() == (
        "9f201e04b49a958a120b2ea2e9cda048d94feddd9278b6fe03fb6cac24c05b83"
    )

    config = extractor.extract_managed_config(sample)

    assert config["protobuf_fields_1_to_9_valid"] is False
    assert config["protobuf_terminal_schema_valid"] is True
    assert config["protobuf_terminal_schema_profile"] == (
        extractor.TERMINAL_SCHEMA_PROFILE_V4_DEFAULT_ELIDED_FIELD_7
    )
    assert config["protobuf_field_numbers"] == [1, 2, 3, 4, 5, 6, 8, 9, 10]
    assert config["protobuf_default_elided_fields"] == [7]
    assert config["version_candidates"] == ["4.4.1"]
    assert len(config["endpoints"]) == 3


@pytest.mark.parametrize("missing_field", [4, 5, 6, 8, 9])
def test_v4_field_7_profile_does_not_make_other_required_fields_optional(
    missing_field: int,
) -> None:
    fields = extractor.parse_protobuf(_v4_default_elided_field_7_message())
    fields.pop(missing_field)

    assert extractor._terminal_schema_profile(fields) is None


def test_v4_field_7_profile_rejects_unknown_or_invalid_field_10() -> None:
    fields = extractor.parse_protobuf(_v4_default_elided_field_7_message())
    fields[11] = [1]
    assert extractor._terminal_schema_profile(fields) is None

    fields.pop(11)
    fields[10] = [2]
    assert extractor._terminal_schema_profile(fields) is None


def test_nested_config_does_not_depend_on_reviewed_outer_field_number() -> None:
    """未知版の外包みfieldでも、内側の厳格なhost/port schemaで回収する。"""

    nested = _bytes_field(1, b"c2.example.test") + _varint(2 << 3) + _varint(56001)
    wrapped = _bytes_field(17, _bytes_field(9, nested))

    raw, fields = extractor.decode_config_blob([_gzip_base64(wrapped)])

    assert raw == nested
    assert fields[1] == [b"c2.example.test"]
    assert fields[2] == [56001]


def test_packed_ports_and_convert_from_base64_whitespace_are_supported() -> None:
    """protobuf-net packed fieldと.NET Base64の空白許容を同時に扱う。"""

    packed = _varint(443) + _varint(56001) + _varint(56002)
    message = _bytes_field(1, b"rat.example") + _bytes_field(2, packed)
    encoded = _gzip_base64(message)
    folded = f" \r\n{encoded[:12]}\t{encoded[12:]}\n"

    _raw, fields = extractor.decode_config_blob([folded])

    assert fields[2] == [443, 56001, 56002]


def test_fixed64_host_bytes_are_not_treated_as_a_string_field() -> None:
    """fixed64をbytesとして保持してもlength-delimited hostへ昇格させない。"""

    message = _fixed64_field(1, b"a.b.test") + _varint_field(2, 443)
    fields = extractor.parse_protobuf(message)

    assert fields[1] == [b"a.b.test"]
    assert fields.wire_types[1] == [1]
    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob([_gzip_base64(message)])


def test_fixed32_terminal_field_cannot_satisfy_string_schema() -> None:
    """値がbytesでもfixed32 fieldをterminal family確証へ使わない。"""

    message = b"".join(
        (
            _bytes_field(1, b"fixed.example"),
            _varint_field(2, 443),
            _fixed32_field(3, b"pfx!"),
            _bytes_field(4, b"Default"),
            _varint_field(5, 1),
            _varint_field(6, 0),
            _bytes_field(7, b""),
            _bytes_field(8, b"APPDATA"),
            _bytes_field(9, b"fixture-mutex"),
        )
    )
    _raw, fields = extractor.decode_config_blob([_gzip_base64(message)])

    assert fields[3] == [b"pfx!"]
    assert fields.wire_types[3] == [5]
    assert extractor._terminal_schema_profile(fields) is None


@pytest.mark.parametrize(
    "message",
    [
        _bytes_field(1, b"single-label") + _varint(2 << 3) + _varint(443),
        _bytes_field(1, b"999.999.999.999") + _varint(2 << 3) + _varint(443),
        _bytes_field(1, b"c2.example") + _varint(2 << 3) + _varint(0),
        _bytes_field(1, b"c2.example")
        + _varint(2 << 3)
        + _varint(443)
        + _varint(2 << 3)
        + _varint(443),
    ],
)
def test_generic_or_invalid_protobuf_is_not_misclassified_as_config(
    message: bytes,
) -> None:
    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob([_gzip_base64(message)])


def test_gzip_trailing_member_and_output_limit_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = _bytes_field(1, b"c2.example") + _varint(2 << 3) + _varint(443)
    compressed = gzip.compress(message, mtime=0)
    trailing = base64.b64encode(compressed + gzip.compress(b"extra", mtime=0)).decode()
    with pytest.raises(
        extractor.ConfigCandidateBoundaryError,
        match="output boundaries",
    ):
        extractor.decode_config_blob([trailing])

    monkeypatch.setattr(extractor, "MAX_CONFIG_CLEAR_BYTES", 8)
    with pytest.raises(
        extractor.ConfigCandidateBoundaryError,
        match="output boundaries",
    ):
        extractor.decode_config_blob([_gzip_base64(message)])


def test_valid_config_is_not_published_after_later_base64_boundary_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """先行候補が妥当でも後続候補を上限で評価できなければfail-closedにする。"""

    message = _bytes_field(1, b"first.example") + _varint_field(2, 443)
    valid = _gzip_base64(message)
    oversized = "H4sI" + ("A" * (len(valid) + 1))
    monkeypatch.setattr(extractor, "MAX_CONFIG_BASE64_CHARS", len(valid))

    with pytest.raises(
        extractor.ConfigCandidateBoundaryError,
        match="Base64 config exceeds",
    ):
        extractor.decode_config_blob([valid, oversized])


def test_valid_config_is_not_published_after_compressed_size_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """復号済み圧縮byte上限も後続候補のno-matchへ降格させない。"""

    message = _bytes_field(1, b"first.example") + _varint_field(2, 443)
    valid_compressed = gzip.compress(message, mtime=0)
    oversized_compressed = gzip.compress(b"A" * 512, compresslevel=0, mtime=0)
    assert len(oversized_compressed) > len(valid_compressed)
    monkeypatch.setattr(
        extractor,
        "MAX_CONFIG_COMPRESSED_BYTES",
        len(valid_compressed),
    )

    with pytest.raises(
        extractor.ConfigCandidateBoundaryError,
        match="compressed config exceeds the input limit",
    ):
        extractor.decode_config_blob(
            [
                base64.b64encode(valid_compressed).decode("ascii"),
                base64.b64encode(oversized_compressed).decode("ascii"),
            ]
        )


def test_valid_raw_config_is_not_published_after_later_output_limit() -> None:
    """raw GZip走査も後続候補の展開上限をno-matchとして捨てない。"""

    message = _bytes_field(1, b"raw.example") + _varint_field(2, 443)
    oversized_clear = b"A" * (extractor.MAX_CONFIG_CLEAR_BYTES + 1)
    carrier = (
        gzip.compress(message, mtime=0)
        + b"separator"
        + gzip.compress(oversized_clear, mtime=0)
    )

    with pytest.raises(
        extractor.ConfigCandidateBoundaryError,
        match="raw GZip candidate violates output boundaries",
    ):
        extractor.decode_config_blob([], raw_blobs=[carrier])


def test_raw_resource_boundary_reason_is_not_masked_by_missing_user_strings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """raw GZip上限を#US不在の一般理由へ置き換えず不完全性を保持する。"""

    carrier = b"MZ managed fixture" + gzip.compress(b"A" * 64, mtime=0)
    monkeypatch.setattr(extractor, "MAX_CONFIG_CLEAR_BYTES", 8)
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(
        extractor,
        "iter_dotnet_user_strings",
        lambda _data: iter(()),
    )
    monkeypatch.setattr(
        extractor,
        "_iter_bounded_embedded_strings",
        lambda _data: iter(()),
    )

    with pytest.raises(
        extractor.ConfigCandidateBoundaryError,
        match="raw GZip candidate violates output boundaries",
    ):
        extractor.extract_managed_config(carrier)


def test_packed_port_limit_does_not_publish_an_earlier_sibling_config() -> None:
    """packed port上限後の未評価値を無視して先行設定を公開しない。"""

    valid = _bytes_field(1, b"valid.example") + _varint_field(2, 443)
    oversized = _bytes_field(1, b"other.example") + _bytes_field(2, b"\x01" * 33)
    wrapped = _bytes_field(17, valid) + _bytes_field(18, oversized)

    with pytest.raises(
        extractor.ConfigCandidateBoundaryError,
        match="packed port list exceeds",
    ):
        extractor.decode_config_blob([_gzip_base64(wrapped)])


def test_raw_managed_resource_string_fallback_uses_same_strict_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#US欠落時もCLR内resourceの設定文字列を回収するが、schemaは緩和しない。"""

    message = _bytes_field(1, b"fallback.example") + _varint(2 << 3) + _varint(56001)
    encoded = _gzip_base64(message)
    monkeypatch.setattr(extractor, "iter_dotnet_user_strings", lambda _data: iter(()))
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(
        extractor,
        "_iter_bounded_embedded_strings",
        lambda _data: iter((encoded, "4.4.1")),
    )

    config = extractor.extract_managed_config(b"MZ managed resource fixture")

    assert config["c2_host"] == "fallback.example"
    assert config["c2_ports"] == [56001]
    assert config["version_candidates"] == ["4.4.1"]


def test_valid_resource_fallback_survives_a_corrupt_user_string_heap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """破損#USは無視せず記録対象だが、独立に妥当なresource configは回収する。"""

    message = _bytes_field(1, b"resource.example") + _varint(2 << 3) + _varint(443)
    encoded = _gzip_base64(message)

    def corrupt_heap(_data: bytes):
        raise extractor._ManagedMetadataError("user_string_heap_size_invalid")
        yield  # pragma: no cover

    monkeypatch.setattr(extractor, "iter_dotnet_user_strings", corrupt_heap)
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(
        extractor,
        "_iter_bounded_embedded_strings",
        lambda _data: iter((encoded,)),
    )

    config = extractor.extract_managed_config(b"MZ managed resource fixture")

    assert config["endpoints"] == ["resource.example:443"]


def test_oversized_managed_input_is_rejected_before_metadata_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        extractor,
        "iter_dotnet_user_strings",
        lambda _data: pytest.fail("過大入力でmetadata parserを呼んではならない"),
    )
    with pytest.raises(
        extractor._ManagedMetadataError,
        match="managed_input_size_exceeded",
    ):
        extractor.extract_managed_config(
            b"MZ" + b"A" * extractor.MAX_MANAGED_TERMINAL_BYTES
        )


def test_user_string_count_limit_reads_one_extra_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(extractor, "MAX_MANAGED_USER_STRINGS", 2)
    monkeypatch.setattr(
        extractor,
        "iter_dotnet_user_strings",
        lambda _data: iter(("first", "second", "third")),
    )
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: False)

    with pytest.raises(
        extractor._ManagedMetadataError,
        match="managed_user_string_count_exceeded",
    ):
        extractor.extract_managed_config(b"MZ managed fixture")


def test_user_string_limit_rejects_valid_resource_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未走査#USとの競合を除外できないためresource成功を公開しない。"""

    message = _bytes_field(1, b"resource.example") + _varint_field(2, 443)
    encoded = _gzip_base64(message)
    monkeypatch.setattr(extractor, "MAX_MANAGED_USER_STRINGS", 1)
    monkeypatch.setattr(
        extractor,
        "iter_dotnet_user_strings",
        lambda _data: iter(("first", "unscanned")),
    )
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(
        extractor,
        "_iter_bounded_embedded_strings",
        lambda _data: iter((encoded,)),
    )

    with pytest.raises(
        extractor._ManagedMetadataError,
        match="managed_user_string_count_exceeded",
    ):
        extractor.extract_managed_config(b"MZ managed resource fixture")


def test_embedded_string_count_limit_reads_one_extra_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(extractor, "MAX_FALLBACK_STRINGS", 1)
    data = b"MZ" + b"A" * 24 + b"\x00" + b"B" * 24

    with pytest.raises(
        extractor._ManagedMetadataError,
        match="managed_embedded_string_count_exceeded",
    ):
        list(extractor._iter_bounded_embedded_strings(data))


def test_conflicting_valid_configs_fail_closed() -> None:
    first = _bytes_field(1, b"first.example") + _varint(2 << 3) + _varint(443)
    second = _bytes_field(1, b"second.example") + _varint(2 << 3) + _varint(56001)

    with pytest.raises(ValueError, match="conflicting managed PureRAT"):
        extractor.decode_config_blob([_gzip_base64(first), _gzip_base64(second)])


def test_duplicate_semantic_config_is_accepted_once() -> None:
    message = _bytes_field(1, b"same.example") + _varint(2 << 3) + _varint(443)

    _raw, fields = extractor.decode_config_blob(
        [_gzip_base64(message), _gzip_base64(message)]
    )

    assert fields[1] == [b"same.example"]
    assert fields[2] == [443]


def test_base64_gzip_candidate_limit_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = _bytes_field(1, b"same.example") + _varint(2 << 3) + _varint(443)
    encoded = _gzip_base64(message)
    monkeypatch.setattr(extractor, "MAX_CONFIG_DECODE_CANDIDATES", 1)

    with pytest.raises(ValueError, match="candidate limit exceeded"):
        extractor.decode_config_blob([encoded, encoded])


def test_nested_message_candidate_limit_is_not_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested = _bytes_field(1, b"nested.example") + _varint(2 << 3) + _varint(443)
    wrapped = _bytes_field(17, nested)
    monkeypatch.setattr(extractor, "MAX_CONFIG_MESSAGE_CANDIDATES", 1)

    with pytest.raises(ValueError, match="nested message candidate limit"):
        extractor.decode_config_blob([_gzip_base64(wrapped)])


def test_nested_protobuf_field_limit_does_not_publish_a_sibling_config() -> None:
    """有効候補の後で上限到達しても、未完了sourceを成功へ降格しない。"""

    valid = _bytes_field(1, b"valid.example") + _varint_field(2, 443)
    oversized = _varint_field(20, 1) * (extractor.MAX_CONFIG_PROTOBUF_FIELDS + 1)
    wrapped = _bytes_field(17, valid) + _bytes_field(18, oversized)

    with pytest.raises(
        extractor.ProtobufLimitError,
        match="protobuf field count exceeds",
    ):
        extractor.decode_config_blob([_gzip_base64(wrapped)])


def test_non_gzip_base64_noise_is_rejected_by_prefilter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        extractor,
        "_decode_base64_gzip",
        lambda _value: pytest.fail("GZip magicなしでdecoderを呼んではならない"),
    )

    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob(["QUFBQUFBQUFBQUFBQUFBQUFB"])


def test_gzip_prefilter_accepts_long_leading_base64_whitespace() -> None:
    message = _bytes_field(1, b"spaced.example") + _varint(2 << 3) + _varint(443)
    encoded = (" " * 64) + "\r\n\t" + _gzip_base64(message)

    _raw, fields = extractor.decode_config_blob([encoded])

    assert fields[1] == [b"spaced.example"]
    assert fields[2] == [443]


def test_embedded_base64_gzip_is_recovered_from_protector_string() -> None:
    """protector文字列の途中に埋め込まれた設定も同じschemaで回収する。"""

    message = _bytes_field(1, b"embedded.example") + _varint(2 << 3) + _varint(56001)
    embedded = f"prefix::{_gzip_base64(message)}::suffix"

    _raw, fields = extractor.decode_config_blob([embedded])

    assert fields[1] == [b"embedded.example"]
    assert fields[2] == [56001]


def test_raw_gzip_member_is_recovered_from_managed_resource_blob() -> None:
    """Base64化されていないraw GZip resourceから設定を回収する。"""

    message = _bytes_field(1, b"raw-resource.example") + _varint(2 << 3) + _varint(443)
    carrier = b"MZ fixture\x00" + gzip.compress(message, mtime=0) + b"\x00overlay"

    _raw, fields = extractor.decode_config_blob([], raw_blobs=[carrier])

    assert fields[1] == [b"raw-resource.example"]
    assert fields[2] == [443]


def test_raw_gzip_only_managed_image_does_not_require_text_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """raw GZipだけのmanaged resourceでも文字列の有無で取りこぼさない。"""

    message = _bytes_field(1, b"raw-only.example") + _varint(2 << 3) + _varint(56001)
    carrier = b"MZ managed fixture\x00" + gzip.compress(message, mtime=0)
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(
        extractor,
        "iter_dotnet_user_strings",
        lambda _data: iter(()),
    )
    monkeypatch.setattr(
        extractor,
        "_iter_bounded_embedded_strings",
        lambda _data: iter(()),
    )

    config = extractor.extract_managed_config(carrier)

    assert config["c2_host"] == "raw-only.example"
    assert config["c2_ports"] == [56001]
    assert config["endpoints"] == ["raw-only.example:56001"]


def test_raw_gzip_scan_is_not_enabled_for_non_managed_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """raw GZip fallbackを一般native blobへ広げない。"""

    message = _bytes_field(1, b"native-no.example") + _varint(2 << 3) + _varint(443)
    carrier = b"native fixture\x00" + gzip.compress(message, mtime=0)
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: False)
    monkeypatch.setattr(
        extractor,
        "iter_dotnet_user_strings",
        lambda _data: iter(()),
    )

    with pytest.raises(
        extractor._ManagedMetadataError,
        match="managed_user_strings_unavailable",
    ):
        extractor.extract_managed_config(carrier)


def test_conflicting_base64_and_raw_configs_fail_closed() -> None:
    """異なる格納方式の相反設定を暗黙に統合しない。"""

    first = _bytes_field(1, b"first.example") + _varint(2 << 3) + _varint(443)
    second = _bytes_field(1, b"second.example") + _varint(2 << 3) + _varint(56001)

    with pytest.raises(ValueError, match="conflicting managed PureRAT"):
        extractor.decode_config_blob(
            [_gzip_base64(first)],
            raw_blobs=[b"prefix" + gzip.compress(second, mtime=0)],
        )


def test_native_endpoint_candidate_count_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """単一文字列内の大量endpointも専用件数上限で拒否する。"""

    monkeypatch.setattr(extractor, "MAX_NATIVE_ENDPOINT_CANDIDATES", 1)

    with pytest.raises(ValueError, match="endpoint candidate limit"):
        extractor.native_endpoint_candidates(["192.0.2.1:443 198.51.100.2:56001"])
