"""PureRAT managed configの版差と安全境界を検証する。"""

from __future__ import annotations

import base64
import gzip

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


def _gzip_base64(value: bytes) -> str:
    return base64.b64encode(gzip.compress(value, mtime=0)).decode("ascii")


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


@pytest.mark.parametrize(
    "message",
    [
        _bytes_field(1, b"single-label") + _varint(2 << 3) + _varint(443),
        _bytes_field(1, b"c2.example") + _varint(2 << 3) + _varint(0),
        _bytes_field(1, b"c2.example")
        + _varint(2 << 3)
        + _varint(443)
        + _varint(2 << 3)
        + _varint(443),
    ],
)
def test_generic_or_invalid_protobuf_is_not_misclassified_as_config(message: bytes) -> None:
    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob([_gzip_base64(message)])


def test_gzip_trailing_member_and_output_limit_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = _bytes_field(1, b"c2.example") + _varint(2 << 3) + _varint(443)
    compressed = gzip.compress(message, mtime=0)
    trailing = base64.b64encode(compressed + gzip.compress(b"extra", mtime=0)).decode()
    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob([trailing])

    monkeypatch.setattr(extractor, "MAX_CONFIG_CLEAR_BYTES", 8)
    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob([_gzip_base64(message)])


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
