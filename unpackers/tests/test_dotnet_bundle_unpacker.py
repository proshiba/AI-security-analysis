from __future__ import annotations

import struct
import zlib

from unpackers.dotnet_bundle_unpacker import (
    BUNDLE_SIGNATURE,
    parse_bundle,
    recover_dotnet_bundle,
)


def _encoded_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    length = len(raw)
    encoded = bytearray()
    while length >= 0x80:
        encoded.append((length & 0x7F) | 0x80)
        length >>= 7
    encoded.append(length)
    return bytes(encoded) + raw


def _bundle(entries: list[tuple[str, int, bytes, bool]]) -> bytes:
    image = bytearray(4096)
    marker_offset = 64
    image[marker_offset : marker_offset + len(BUNDLE_SIGNATURE)] = BUNDLE_SIGNATURE
    cursor = 256
    manifest_entries = bytearray()
    recovered_total = 0
    for name, file_type, content, compress in entries:
        if compress:
            compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
            stored = compressor.compress(content) + compressor.flush()
            compressed_size = len(stored)
        else:
            stored = content
            compressed_size = 0
        image[cursor : cursor + len(stored)] = stored
        manifest_entries.extend(struct.pack("<qqqB", cursor, len(content), compressed_size, file_type))
        manifest_entries.extend(_encoded_string(name))
        cursor += len(stored) + 8
        recovered_total += len(content)

    header_offset = cursor
    struct.pack_into("<q", image, marker_offset - 8, header_offset)
    header = bytearray(struct.pack("<IIi", 6, 0, len(entries)))
    header.extend(_encoded_string("fixture-id"))
    header.extend(struct.pack("<qqqqQ", 0, 0, 0, 0, 0))
    header.extend(manifest_entries)
    image[header_offset : header_offset + len(header)] = header
    return bytes(image[: header_offset + len(header)])


def test_recovers_compressed_and_uncompressed_entries() -> None:
    managed = b"MZ" + b"managed-app" * 100
    config = b'{"runtimeOptions":{}}'
    data = _bundle(
        [
            ("sample.dll", 1, managed, True),
            ("sample.runtimeconfig.json", 4, config, False),
        ]
    )

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "recovered"
    assert report["version"] == "6.0"
    assert report["entry_count"] == 2
    assert report["declared_total_size"] == len(managed) + len(config)
    assert report["executed"] is False
    assert artifacts == [
        ("dotnet-bundle-assembly", managed),
        ("dotnet-bundle-runtime_config_json", config),
    ]


def test_runtime_assemblies_are_inventoried_without_recursive_analysis() -> None:
    """標準runtimeはhash台帳へ残し、アプリと非標準依存関係だけを再帰解析する。"""

    app = b"MZapplication"
    runtime = b"MZruntime"
    dependency = b"MZthird-party"
    config = b'{"runtimeOptions":{}}'
    data = _bundle(
        [
            ("Acme.Tool.dll", 1, app, False),
            ("System.Private.CoreLib.dll", 1, runtime, False),
            ("ThirdParty.Helper.dll", 1, dependency, False),
            ("Acme.Tool.runtimeconfig.json", 4, config, False),
        ]
    )

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "recovered"
    assert report["recovered_count"] == 4
    assert report["analysis_artifact_count"] == 3
    assert report["analysis_excluded_count"] == 1
    assert report["application_stems"] == ["acme.tool"]
    assert artifacts == [
        ("dotnet-bundle-assembly", app),
        ("dotnet-bundle-assembly", dependency),
        ("dotnet-bundle-runtime_config_json", config),
    ]
    runtime_item = next(
        item for item in report["inventory"] if item["name"] == "System.Private.CoreLib.dll"
    )
    assert runtime_item["analysis_selected"] is False
    assert runtime_item["analysis_selection_reason"] == "dotnet_runtime_inventory_only"
    assert runtime_item["sha256"]

def test_rejects_traversal_path() -> None:
    data = _bundle([("../payload.dll", 1, b"MZfixture", False)])

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "parse_failed"
    assert "安全ではありません" in report["error"]
    assert artifacts == []


def test_rejects_entry_total_budget() -> None:
    data = _bundle([("payload.dll", 1, b"MZ" + b"X" * 128, False)])

    report, artifacts = recover_dotnet_bundle(data, max_total_size=64)

    assert report["status"] == "parse_failed"
    assert "合計サイズ" in report["error"]
    assert artifacts == []


def test_parse_reports_header_and_manifest_offsets() -> None:
    data = _bundle([("payload.dll", 1, b"MZfixture", False)])

    report, entries = parse_bundle(data)

    assert 0 < report["marker_offset"] < report["header_offset"]
    assert report["manifest_end_offset"] <= len(data)
    assert entries[0].relative_path == "payload.dll"
