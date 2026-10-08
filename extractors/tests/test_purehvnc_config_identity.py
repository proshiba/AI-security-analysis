"""PureRAT既知設定のhost表記同値と静的抽出境界を人工bytesで検証する。"""

from __future__ import annotations

import base64
import gzip
import hashlib
import struct

import pytest

from extractors.purehvnc import extractor


def _varint(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def _field(number, value):
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def _message(host, ports=(443, 56001), extra=b"", packed=False):
    return (
        _field(1, host.encode())
        + (
            _field(2, b"".join(_varint(port) for port in ports))
            if packed
            else b"".join(_varint(16) + _varint(port) for port in ports)
        )
        + extra
    )


def _encoded(message, wrapper=None):
    if wrapper is not None:
        message = _field(wrapper, message)
    return base64.b64encode(gzip.compress(message, mtime=0)).decode()


def _compressed_length(value):
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([(value >> 8) | 0x80, value & 255])
    return bytes(
        [(value >> 24) | 0xC0, (value >> 16) & 255, (value >> 8) & 255, value & 255]
    )


def _managed_pe(strings):
    """CLI headerと実#US heapを持つ不活性な人工PEをmemoryで構成する。"""
    user_strings = bytearray(b"\0")
    for value in strings:
        raw = value.encode("utf-16le") + b"\0"
        user_strings += _compressed_length(len(raw)) + raw
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, 0, 0)
    streams = [
        (b"#~\0", tables),
        (b"#Strings\0", b"\0"),
        (b"#US\0", bytes(user_strings)),
    ]
    version = b"v4.0.30319\0\0\0"
    header = bytearray(
        struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version))
        + version
        + struct.pack("<HH", 0, len(streams))
    )
    stream_header_size = sum(8 + ((len(name) + 3) & ~3) for name, _ in streams)
    offset = len(header) + stream_header_size
    stream_data = bytearray()
    for name, content in streams:
        header += struct.pack("<II", offset + len(stream_data), len(content)) + name
        header += b"\0" * ((-len(name)) % 4)
        stream_data += content
    metadata = bytes(header + stream_data)
    data = bytearray(0x2000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 14 * 8, 0x1000, 0x48)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1800, 0x1000, 0x1E00, 0x200)
    struct.pack_into("<I", data, section + 36, 0x40000040)
    struct.pack_into("<IHHII", data, 0x200, 0x48, 2, 5, 0x1080, len(metadata))
    struct.pack_into("<I", data, 0x210, 1)
    data[0x280 : 0x280 + len(metadata)] = metadata
    return bytes(data)


@pytest.mark.parametrize("host", ["SAME.Example", "same.example.", "SAME.EXAMPLE."])
@pytest.mark.parametrize("packed,wrapper", [(False, None), (True, 17), (False, 38)])
def test_host_spelling_equivalence_recovers_one_config(host, packed, wrapper):
    values = [
        _encoded(_message("same.example")),
        _encoded(_message(host, packed=packed), wrapper),
    ]
    raw, fields = extractor.decode_config_blob(values)
    assert raw == _message("same.example")
    assert fields[1] == [b"same.example"]
    assert fields[2] == [443, 56001]


@pytest.mark.parametrize(
    "changed",
    [
        _message("other.example"),
        _message("same.example", (443, 56002)),
        _message("same.example", (56001, 443)),
        _message("same.example", extra=_field(9, b"mutex-two")),
        _message("same.example", extra=_field(3, b"certificate-two")),
        _message("same.example", extra=_field(24, b"unknown-two")),
        _message("same.example", extra=_field(1, b"second.example")),
    ],
)
def test_real_difference_remains_conflicting(changed):
    with pytest.raises(
        ValueError, match="conflicting managed|host field multiplicity is unsupported"
    ):
        extractor.decode_config_blob(
            [_encoded(_message("same.example")), _encoded(changed)]
        )


@pytest.mark.parametrize(
    "left,right", [("same.example", "same.example.."), ("k.example", "\u212a.example")]
)
def test_unreviewed_unicode_or_double_dot_alias_is_not_merged(left, right):
    with pytest.raises(ValueError, match="conflicting managed"):
        extractor.decode_config_blob(
            [_encoded(_message(left)), _encoded(_message(right))]
        )


def test_normal_entry_recovers_from_real_synthetic_user_string_heap():
    values = [
        _encoded(_message("same.example")),
        _encoded(_message("SAME.EXAMPLE.", packed=True), 19),
        "4.4.1",
    ]
    data = _managed_pe(values)
    assert extractor.has_clr_metadata(data)
    assert set(values).issubset(set(extractor.iter_dotnet_user_strings(data)))
    result = extractor.extract(data, "synthetic.exe")
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["decoded_config_recovered"] is True
    assert result["config"]["endpoints"] == ["same.example:443", "same.example:56001"]
    assert result["config"]["version_candidates"] == ["4.4.1"]
    assert result["executed"] is False
    assert result["network_contacted"] is False
    assert result["credentials_published"] is False
    assert all(
        item["confidence"] == "confirmed_static_configuration" for item in result["c2"]
    )


@pytest.mark.parametrize(
    "host", ["same.example", "SAME.EXAMPLE.", "2001:DB8::1", "192.0.2.1"]
)
def test_single_candidate_preserves_full_existing_contract(host):
    data = _managed_pe([_encoded(_message(host)), "4.4.1"])
    canonical = host.lower().rstrip(".")
    ports = [443, 56001]
    endpoints = [f"{canonical}:{port}" for port in ports]
    expected = {
        "schema_version": 1,
        "family": "purehvnc",
        "sample_sha256": hashlib.sha256(data).hexdigest(),
        "config": {
            "variant": "managed_purerat",
            "protobuf_fields_1_to_9_valid": False,
            "c2_host": canonical,
            "c2_ports": ports,
            "campaign_id": "",
            "persistence": False,
            "prevent_sleep": False,
            "scheduled_task": "",
            "install_environment": "",
            "mutex": "",
            "endpoints": endpoints,
            "version_candidates": ["4.4.1"],
            "static_config_recovered": True,
            "decoded_config_recovered": True,
            "status": "managed_terminal_config_recovered",
            "recovery_reason": "managed_base64_or_raw_gzip_protobuf_config",
            "terminal_family_confirmed": False,
            "family_attribution_confirmed": False,
            "terminal_family_confirmation_requires_detector": True,
            "source_name": "synthetic.exe",
        },
        "findings": [
            {
                "kind": "network.endpoint",
                "value": endpoint,
                "role": "configured_c2",
                "confidence": "confirmed",
                "source": "static_config",
            }
            for endpoint in endpoints
        ],
        "limitations": [
            "静的抽出だけを実施し、payload実行やC2への接続は行っていない。"
        ],
        "credentials_published": False,
        "executed": False,
        "network_contacted": False,
        "c2": [
            {
                "host": canonical,
                "port": port,
                "role": "c2",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "managed_base64_gzip_protobuf_config",
                    "variant": "managed_purerat",
                    "host_and_ports_validated": True,
                    "endpoint_correlated": True,
                },
            }
            for port in ports
        ],
    }
    assert extractor.extract(data, "synthetic.exe") == expected


def test_canonical_duplicates_cannot_bypass_candidate_limit():
    with pytest.raises(ValueError, match="candidate limit exceeded"):
        extractor.decode_config_blob([_encoded(_message("SAME.EXAMPLE."))] * 65)


@pytest.mark.parametrize(
    "invalid",
    [
        gzip.compress(_message("same.example")) + b"tail",
        gzip.compress(_message("same.example")) + gzip.compress(b"extra"),
        b"not-gzip",
        gzip.compress(_message("single-label")),
        gzip.compress(_message("same.example", (0,))),
    ],
)
def test_compression_and_config_boundaries_remain_fail_closed(invalid):
    with pytest.raises(ValueError, match="config was not found"):
        extractor.decode_config_blob([base64.b64encode(invalid).decode()])


def test_oversized_managed_input_still_fails_before_metadata():
    with pytest.raises(
        extractor._ManagedMetadataError, match="managed_input_size_exceeded"
    ):
        extractor.extract_managed_config(
            b"MZ" + bytes(extractor.MAX_MANAGED_TERMINAL_BYTES)
        )
