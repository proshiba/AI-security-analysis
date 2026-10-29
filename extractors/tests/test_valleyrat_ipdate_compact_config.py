"""ValleyRAT ``IpDate`` compact設定routeの回帰テスト。"""

from __future__ import annotations

import struct

import pytest

from extractors.valleyrat import ipdate_compact_config as profile
from extractors.valleyrat.extractor import extract

_IMAGE_BASE = 0x180000000
_FILE_ALIGNMENT = 0x200
_SECTION_ALIGNMENT = 0x1000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _pe64(sections: list[tuple[bytes, bytes, int]]) -> bytes:
    """name、content、characteristicsから最小file-layout PE32+を作る。"""

    headers_size = 0x400
    section_rows: list[tuple[bytes, bytes, int, int, int, int]] = []
    raw_offset = headers_size
    virtual_address = 0x1000
    for name, content, characteristics in sections:
        raw_size = _align(len(content), _FILE_ALIGNMENT)
        section_rows.append(
            (name, content, characteristics, raw_offset, virtual_address, raw_size)
        )
        raw_offset += raw_size
        virtual_address += _align(max(1, len(content)), _SECTION_ALIGNMENT)
    image = bytearray(raw_offset)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x84,
        0x8664,
        len(section_rows),
        0,
        0,
        0,
        0xF0,
        0x2022,
    )
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 20, 0x1000)
    struct.pack_into("<Q", image, optional + 24, _IMAGE_BASE)
    struct.pack_into("<II", image, optional + 32, _SECTION_ALIGNMENT, _FILE_ALIGNMENT)
    struct.pack_into("<I", image, optional + 56, virtual_address)
    struct.pack_into("<I", image, optional + 60, headers_size)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<I", image, optional + 108, 16)
    table = optional + 0xF0
    for index, row in enumerate(section_rows):
        name, content, characteristics, raw, rva, raw_size = row
        header = table + index * 40
        image[header : header + 8] = name.ljust(8, b"\x00")[:8]
        struct.pack_into("<IIII", image, header + 8, len(content), rva, raw_size, raw)
        struct.pack_into("<I", image, header + 36, characteristics)
        image[raw : raw + len(content)] = content
    return bytes(image)


def _sample(
    *configs: str,
    encoding: str = "ascii",
    values: tuple[str, ...] = ("IpDate", "IpDateInfo"),
    section_name: bytes = b".rdata",
    extra: bytes = b"",
) -> bytes:
    strings = ["Software\\Console", *values, *configs]
    separator = b"\x00" if encoding == "ascii" else b"\x00\x00"
    content = separator.join(item.encode(encoding) for item in strings)
    content += separator + extra
    return _pe64(
        [
            (b".text", b"\xc3", 0x60000020),
            (section_name, content, 0x40000040),
        ]
    )


def _all_text(value: object) -> str:
    if isinstance(value, dict):
        return "\n".join(f"{key}\n{_all_text(item)}" for key, item in value.items())
    if isinstance(value, list):
        return "\n".join(_all_text(item) for item in value)
    return str(value)


def test_ascii_compact_literal_is_route_only_candidate() -> None:
    recovered = profile.extract_ipdate_compact_config(
        _sample("i:154.39.255.141|p:5689")
    )

    assert recovered["endpoint"] == "154.39.255.141:5689"
    assert recovered["endpoint_role"] == "interactive_c2_candidate"
    assert recovered["candidate_config_recovered"] is True
    assert recovered["static_config_recovered"] is False
    assert recovered["supports_family_attribution"] is False
    assert recovered["terminal_family_confirmed"] is False
    assert recovered["command_c2_confirmed"] is False
    assert recovered["evidence"]["runtime_registry_value_observed"] is False
    assert recovered["evidence"]["compact_literal_encodings"] == ["ascii"]
    assert recovered["safety"]["sample_executed"] is False
    assert recovered["safety"]["network_contacted"] is False


def test_utf16le_compact_literal_and_separate_value_names_are_supported() -> None:
    recovered = profile.extract_ipdate_compact_config(
        _sample(
            "i:c2.example.net|p:443|",
            encoding="utf-16le",
            values=("IpDateInfo", "SelfPath"),
        )
    )

    assert recovered["endpoint"] == "c2.example.net:443"
    assert recovered["evidence"]["compact_literal_encodings"] == ["utf-16le"]
    assert recovered["evidence"]["registry_value_markers"] == [
        "IpDateInfo",
        "SelfPath",
    ]


def test_detector_probe_hides_endpoint_and_raw_strings() -> None:
    result = profile.probe_ipdate_compact_config(_sample("i:198.51.100.7|p:443"))

    # TEST-NETはpublic endpointではないためprobeは拒否し、値も返さない。
    assert result["matched"] is False
    assert result["endpoint_count"] == 0
    text = _all_text(result)
    assert "198.51.100.7" not in text
    assert "i:198.51.100.7|p:443" not in text


def test_successful_probe_hides_public_endpoint() -> None:
    result = profile.probe_ipdate_compact_config(_sample("i:154.39.255.141|p:5689"))

    assert result["matched"] is True
    assert result["endpoint_count"] == 1
    text = _all_text(result)
    assert "154.39.255.141" not in text
    assert "i:154.39.255.141|p:5689" not in text


def test_common_extractor_preserves_route_only_evidence_boundary() -> None:
    result = extract(_sample("i:154.39.255.141|p:5689"), "compact.dll")

    assert result["family"] == "valleyrat"
    assert result["config"]["variant"] == "ipdate_compact_embedded_literal_candidate"
    assert result["config"]["endpoints"] == ["154.39.255.141:5689"]
    assert result["config"]["candidate_config_recovered"] is True
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["supports_family_attribution"] is False
    finding = next(
        item for item in result["findings"] if item["kind"] == "network.endpoint"
    )
    assert finding["role"] == "interactive_c2_candidate"
    assert result["config"]["recovery_diagnostics"]["status"] == "route_only"


@pytest.mark.parametrize(
    "values",
    [(), ("IpDate",), ("Unrelated", "SelfPath")],
)
def test_requires_registry_base_and_two_known_value_markers(
    values: tuple[str, ...],
) -> None:
    with pytest.raises(
        profile.IpDateCompactConfigError,
        match="IpDate marker候補|複数のIpDate系value名",
    ):
        profile.extract_ipdate_compact_config(
            _sample("i:154.39.255.141|p:5689", values=values)
        )


@pytest.mark.parametrize(
    "config",
    [
        "i:127.0.0.1|p:5689",
        "i:10.0.0.1|p:5689",
        "i:192.0.2.10|p:5689",
        "i:c2.example|p:5689",
        "i:host.invalid|p:5689",
        "i:154.39.255.141|p:0",
        "i:154.39.255.141|p:65536",
    ],
)
def test_non_public_or_invalid_endpoints_are_rejected(config: str) -> None:
    with pytest.raises(profile.IpDateCompactConfigError, match="literalがありません"):
        profile.extract_ipdate_compact_config(_sample(config))


def test_conflicting_compact_literals_are_fail_closed() -> None:
    with pytest.raises(profile.IpDateCompactConfigError, match="相反"):
        profile.extract_ipdate_compact_config(
            _sample(
                "i:154.39.255.141|p:5689",
                "i:143.92.38.217|p:443",
            )
        )


def test_duplicate_same_endpoint_across_encodings_is_not_ambiguous() -> None:
    ascii_block = b"Software\\Console\0IpDate\0IpDateInfo\0i:154.39.255.141|p:5689\0"
    wide_block = (
        "Software\\Console\0IpDate\0IpDateInfo\0i:154.39.255.141|p:5689\0"
    ).encode("utf-16le")
    data = _pe64(
        [
            (b".text", b"\xc3", 0x60000020),
            (b".rdata", ascii_block + wide_block, 0x40000040),
        ]
    )

    recovered = profile.extract_ipdate_compact_config(data)

    assert recovered["endpoint"] == "154.39.255.141:5689"
    assert recovered["evidence"]["compact_literal_occurrence_count"] == 2
    assert recovered["evidence"]["compact_literal_encodings"] == [
        "ascii",
        "utf-16le",
    ]


@pytest.mark.parametrize(
    "config",
    [
        "prefix-i:154.39.255.141|p:5689",
        "i:154.39.255.141|p:5689-suffix",
        "i:154.39.255.141|p:5689|extra:1",
    ],
)
def test_compact_literal_requires_whole_string_match(config: str) -> None:
    with pytest.raises(profile.IpDateCompactConfigError, match="literalがありません"):
        profile.extract_ipdate_compact_config(_sample(config))


def test_resource_and_overlay_decoys_are_not_scanned() -> None:
    marker_block = b"Software\\Console\0IpDate\0IpDateInfo\0i:154.39.255.141|p:5689\0"
    resource_only = _pe64(
        [
            (b".text", b"\xc3", 0x60000020),
            (b".rsrc", marker_block, 0x40000040),
        ]
    )
    overlay_only = (
        _pe64(
            [
                (b".text", b"\xc3", 0x60000020),
                (b".rdata", b"ordinary\0", 0x40000040),
            ]
        )
        + marker_block
    )

    for data in (resource_only, overlay_only):
        with pytest.raises(profile.IpDateCompactConfigError):
            profile.extract_ipdate_compact_config(data)


def test_string_length_limit_is_fail_closed() -> None:
    data = _sample(
        "i:154.39.255.141|p:5689",
        extra=b"A" * (profile.MAXIMUM_STRING_LENGTH + 1),
    )

    with pytest.raises(profile.IpDateCompactConfigError, match="文字列が上限"):
        profile.extract_ipdate_compact_config(data)


def test_input_type_size_and_pe_shape_are_rejected_before_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(profile.IpDateCompactConfigError, match="bytes"):
        profile.extract_ipdate_compact_config(bytearray(b"MZ"))  # type: ignore[arg-type]
    with pytest.raises(profile.IpDateCompactConfigError, match="PEではありません"):
        profile.extract_ipdate_compact_config(b"not a pe")

    monkeypatch.setattr(profile, "MAXIMUM_INPUT_SIZE", 8)
    with pytest.raises(profile.IpDateCompactConfigError, match="size"):
        profile.extract_ipdate_compact_config(b"MZ" + b"\0" * 7)
