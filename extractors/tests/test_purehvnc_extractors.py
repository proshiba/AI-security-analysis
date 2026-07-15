"""Unit tests for PureHVNC and DonutLoader extraction helpers."""

from __future__ import annotations

import base64
import gzip

import pytest

from extractors.donutloader.extractor import layer_markers
from extractors.purehvnc.extractor import decode_config_blob, extract_native_config, parse_protobuf, read_varint


def varint(value: int) -> bytes:
    """Encode a test varint."""
    output = bytearray()
    while value > 0x7F:
        output.append(value & 0x7F | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number: int, value: bytes) -> bytes:
    """Encode a test length field."""
    return varint(number << 3 | 2) + varint(len(value)) + value


def test_protobuf_and_config_blob() -> None:
    """Parse nested Base64/GZip PureRAT configuration fields."""
    nested = field(1, b"example.test") + varint(2 << 3) + varint(56001)
    outer = field(38, nested)
    encoded = base64.b64encode(gzip.compress(outer)).decode()
    blob, fields = decode_config_blob(["noise", encoded])
    assert blob == nested
    assert fields[1] == [b"example.test"]
    assert fields[2] == [56001]
    assert parse_protobuf(nested)[1][0] == b"example.test"
    assert read_varint(varint(300), 0)[0] == 300


def test_native_profile_and_layer_markers() -> None:
    """Extract a native fixture and classify common delivery layers."""
    config = extract_native_config(b"10FX\0START_SCREEN\0" + b"154.82.93.206:8080\0")
    assert "154.82.93.206:8080" in config["endpoints"]
    assert layer_markers(b"MZ CHRD PayloadSource.zip") == ["chrd_config", "managed_payload_resource", "portable_executable"]
    with pytest.raises(ValueError):
        extract_native_config(b"unrelated")
