from __future__ import annotations

import base64
import struct
import zlib
from types import SimpleNamespace

import pytest

from unpackers import dotnet_bundle_unpacker as bundle_unpacker
from unpackers.dotnet_bundle_unpacker import (
    BUNDLE_SIGNATURE,
    parse_bundle,
    recover_dotnet_bundle,
)

_MANAGED_FIXTURE_ZLIB_B64 = (
    "eNrtVd9rXEUU/u7dbdkmNka0oX2pN90UROplJYtUKZpsNk1Tk27IbqOosLl7d7q55e6dy9y5cSMi9aGIbz75Xij4otIHwVrsX6AF"
    "/4T8AYKvImg8M3P3R35gofjWnmTOzJz5zpnvnJk7u/rBV8gByFPb2wPuw8gcHi+3qE28/GACP5x4NH3fWnk03dgKEicWvCO8ruN7"
    "UcSl02KOSCMniJxqre50eZu5J0+OzWQx1haBFSuHbx+2bvbj7sKeHrfGDanjxna2SMoZEJvUY9tAgGGvSdlmmMPcbQVV/8N+0Gn5"
    "7Rzwbj/h3BFJbgLP4QmE+BVGpgWaXxmZu5L1JPUzuSyv/JD3SIhNVyTCR8ZtDvtqguFZzbmChdzPuG5mscYO4SqHeBZNd0W7HEOD"
    "Nv2UfC08mYzZr6JSv1qxsgiKz3bZLbmzpdnX31SWYwhJ/6q2/gy4SLDf1bguRRB1EoWYsU3titfruGCb8youXV+uUn/JNmUoVkLe"
    "yvZUdJdOASfU5K/zs5gy/HNZGays2QfmqkCmP44GVkl/gQ7p70hjgFGZfG5N4jW8QdzVbE2dF77Gh5m/BQ8v4Bs8jzOkX4KLcZwm"
    "/SKmkb91sEK/jN5W7V3tDy+t8nYasrfR5jJisilYwlPhs2bIvTYTzRtBT6aCue0wxHKbRTKQO6hLTwb+ZbOEbuJzEQYt1HcSybqo"
    "tW4yX2I+jsMdbHthyrIVdz0l/y5zF3g3DkIm6kxsBz5LYAwUlEfrLPR6epTMSzqgVioZXF9ygcxdgQnQCkLiMsT8dwL6Pusi4u87"
    "b927XVu6+tOdn6cenPq+gsKPn3y0caa8+2UeVqGQdyyrQFCrYGWf01l1Ag176j3hxdd4tNjzWawINrYE/zix/jw3rOxE/804Sor9"
    "QXOBi2oYrnpBZKrHTIGV7J0n/0k8NWLpZE+bV3SfXd3z0hH2/tvxPn2Ud0fer7t2mfQG6miSXsQ6jZZRwzWaL5O+TGMlD/N//HPU"
    "a/POyLt+4FnU34tFUT0IihPQe8IoZoQb4Hp9Rns1aNUja0LrHiThOM2M3Mvn9RtXJ7uglYi++MORdi2FKQ3+ymipGuACMbIG+Cq1"
    "BL6OE+/bx9E1K4xgN6gJQg8xJXonhg3YootpaQ5SYyPiHlK9PHShvps2eUqyMtJNWld7c6Q08mncJCwnbFv7NimPAD1Cphrpkj2E"
    "udmv6BxWyNrROyyQX4wdnUWHWMiMf6z51DJ7kPHp5xP977zKul5rZOdkTclbHqrawZpd1D7zhEgI2aVTCikT57F+z8QcsvqNdmaf"
    "leJplH8BB7klug=="
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


def _bundle(
    entries: list[tuple[str, int, bytes, bool]],
    *,
    major: int = 6,
) -> bytes:
    image = bytearray(4096)
    marker_offset = 64
    image[marker_offset : marker_offset + len(BUNDLE_SIGNATURE)] = BUNDLE_SIGNATURE
    cursor = 256
    manifest_entries = bytearray()
    recovered_total = 0
    for name, file_type, content, compress in entries:
        if major < 6 and compress:
            raise ValueError("bundle v2 fixtureは圧縮entryを表現できません")
        if compress:
            compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
            stored = compressor.compress(content) + compressor.flush()
            compressed_size = len(stored)
        else:
            stored = content
            compressed_size = 0
        image[cursor : cursor + len(stored)] = stored
        if major >= 6:
            manifest_entries.extend(
                struct.pack("<qqqB", cursor, len(content), compressed_size, file_type)
            )
        else:
            manifest_entries.extend(struct.pack("<qqB", cursor, len(content), file_type))
        manifest_entries.extend(_encoded_string(name))
        cursor += len(stored) + 8
        recovered_total += len(content)

    header_offset = cursor
    struct.pack_into("<q", image, marker_offset - 8, header_offset)
    header = bytearray(struct.pack("<IIi", major, 0, len(entries)))
    header.extend(_encoded_string("fixture-id"))
    header.extend(struct.pack("<qqqqQ", 0, 0, 0, 0, 0))
    header.extend(manifest_entries)
    image[header_offset : header_offset + len(header)] = header
    return bytes(image[: header_offset + len(header)])


def _managed_runtime_fixture() -> bytes:
    """CLR Assembly/Module identityをsynthetic runtime名へ置換した無害fixture。"""

    raw = zlib.decompress(base64.b64decode(_MANAGED_FIXTURE_ZLIB_B64))
    old = b"dotnet_resource_loader_fixture"
    replacement = b"System.Private.CoreLib" + (b"\0" * 8)
    assert len(old) == len(replacement)
    assert raw.count(old) == 2
    return raw.replace(old, replacement)


def _bundle_with_raw_deflate(
    content: bytes,
    *,
    declared_size: int | None = None,
    truncate: int = 0,
    trailing: bytes = b"",
) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    stored = compressor.compress(content) + compressor.flush()
    if truncate:
        stored = stored[:-truncate]
    stored += trailing

    entry_offset = 256
    image = bytearray(max(4096, entry_offset + len(stored) + 512))
    marker_offset = 64
    image[marker_offset : marker_offset + len(BUNDLE_SIGNATURE)] = BUNDLE_SIGNATURE
    image[entry_offset : entry_offset + len(stored)] = stored
    header_offset = entry_offset + len(stored) + 8
    struct.pack_into("<q", image, marker_offset - 8, header_offset)
    header = bytearray(struct.pack("<IIi", 6, 0, 1))
    header.extend(_encoded_string("fixture-id"))
    header.extend(struct.pack("<qqqqQ", 0, 0, 0, 0, 0))
    header.extend(
        struct.pack(
            "<qqqB",
            entry_offset,
            len(content) if declared_size is None else declared_size,
            len(stored),
            1,
        )
    )
    header.extend(_encoded_string("sample.dll"))
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


def test_compressed_entry_output_is_bounded_to_declared_size_plus_one() -> None:
    declared_size = 32
    data = _bundle_with_raw_deflate(
        b"A" * (4 * 1024 * 1024), declared_size=declared_size
    )

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "partially_recovered"
    assert report["recovered_count"] == 0
    assert artifacts == []
    item = report["inventory"][0]
    assert item["status"] == "size_mismatch_blocked"
    assert item["declared_size"] == declared_size
    assert item["actual_size"] == declared_size + 1
    assert item["actual_size_is_lower_bound"] is True


def test_compressed_entry_requires_exact_declared_size() -> None:
    content = b"MZfixture" * 8
    data = _bundle_with_raw_deflate(content, declared_size=len(content) + 1)

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "partially_recovered"
    assert artifacts == []
    item = report["inventory"][0]
    assert item["status"] == "size_mismatch_blocked"
    assert item["actual_size"] == len(content)
    assert item["actual_size_is_lower_bound"] is False


def test_compressed_entry_rejects_truncated_stream() -> None:
    data = _bundle_with_raw_deflate(b"MZfixture" * 64, truncate=1)

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "partially_recovered"
    assert artifacts == []
    item = report["inventory"][0]
    assert item["status"] == "decompression_failed"
    assert item["error"] == "incomplete_deflate_stream"


def test_compressed_entry_rejects_trailing_data() -> None:
    data = _bundle_with_raw_deflate(b"MZfixture" * 64, trailing=b"trailing")

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "partially_recovered"
    assert artifacts == []
    item = report["inventory"][0]
    assert item["status"] == "decompression_failed"
    assert item["error"] == "trailing_data_after_deflate_stream"


@pytest.mark.parametrize("major", [2, 6])
def test_runtime_name_without_matching_content_is_selected_for_analysis(major: int) -> None:
    """runtime名で偽装したentryをv2/v6のどちらでも除外しない。"""

    app = b"MZapplication"
    disguised_payload = b"MZruntime-name-only-payload"
    dependency = b"MZthird-party"
    config = b'{"runtimeOptions":{}}'
    data = _bundle(
        [
            ("Acme.Tool.dll", 1, app, False),
            ("System.Private.CoreLib.dll", 1, disguised_payload, False),
            ("ThirdParty.Helper.dll", 1, dependency, False),
            ("Acme.Tool.runtimeconfig.json", 4, config, False),
        ],
        major=major,
    )

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "recovered"
    assert report["version"] == f"{major}.0"
    assert report["recovered_count"] == 4
    assert report["analysis_artifact_count"] == 4
    assert report["analysis_excluded_count"] == 0
    assert report["application_stems"] == ["acme.tool"]
    assert artifacts == [
        ("dotnet-bundle-assembly", app),
        ("dotnet-bundle-assembly", disguised_payload),
        ("dotnet-bundle-assembly", dependency),
        ("dotnet-bundle-runtime_config_json", config),
    ]
    runtime_item = next(
        item for item in report["inventory"] if item["name"] == "System.Private.CoreLib.dll"
    )
    assert runtime_item["analysis_selected"] is True
    assert runtime_item["analysis_selection_reason"] == (
        "managed_runtime_name_content_mismatch_requires_analysis"
    )
    assert runtime_item["analysis_content_evidence"]["managed_metadata_validated"] is False
    assert runtime_item["sha256"]


@pytest.mark.parametrize("major", [2, 6])
def test_content_consistent_runtime_is_still_selected_for_bounded_audit(major: int) -> None:
    """identityが整合しても名前は偽装可能なため、予算内では再帰解析する。"""

    runtime = _managed_runtime_fixture()
    data = _bundle(
        [("System.Private.CoreLib.dll", 1, runtime, False)],
        major=major,
    )

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "recovered"
    assert artifacts == [("dotnet-bundle-assembly", runtime)]
    item = report["inventory"][0]
    assert item["analysis_selected"] is True
    assert item["analysis_selection_reason"] == (
        "managed_runtime_identity_consistent_bounded_audit"
    )
    assert item["analysis_content_evidence"] == {
        "status": "runtime_identity_consistent",
        "expected_extension_valid": True,
        "content_probe_within_budget": True,
        "managed_metadata_validated": True,
        "assembly_identity_matches_basename": True,
        "module_identity_matches_basename": True,
    }


def test_content_consistent_runtime_is_omitted_only_by_explicit_budget() -> None:
    """低優先runtimeを件数予算で省略した場合はpartialと未完了数を残す。"""

    app = b"MZapplication"
    runtime = _managed_runtime_fixture()
    data = _bundle(
        [
            ("Acme.Tool.dll", 1, app, False),
            ("System.Private.CoreLib.dll", 1, runtime, False),
            ("Acme.Tool.runtimeconfig.json", 4, b"{}", False),
        ]
    )

    report, artifacts = recover_dotnet_bundle(
        data,
        max_analysis_artifacts=2,
        max_analysis_bytes=len(app) + 2,
    )

    assert report["status"] == "analysis_budget_partial"
    assert artifacts == [
        ("dotnet-bundle-assembly", app),
        ("dotnet-bundle-runtime_config_json", b"{}"),
    ]
    runtime_item = report["inventory"][1]
    assert runtime_item["analysis_selected"] is False
    assert runtime_item["analysis_candidate_reason"] == (
        "managed_runtime_identity_consistent_bounded_audit"
    )
    assert runtime_item["analysis_selection_reason"] == "analysis_count_budget_inventory_only"
    assert report["analysis_budget"]["budget_exhausted"] is True
    assert report["analysis_budget"]["selection_complete"] is False
    assert report["analysis_budget"]["omitted_unique_artifact_count"] == 1


def test_native_runtime_name_and_symbol_type_do_not_hide_payloads() -> None:
    """native runtime名またはsymbols型だけではPE風payloadを除外しない。"""

    native_disguise = b"MZ-not-coreclr"
    symbol_disguise = b"MZ-not-a-pdb"
    data = _bundle(
        [
            ("coreclr.dll", 2, native_disguise, False),
            ("payload.pdb", 5, symbol_disguise, False),
        ]
    )

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "recovered"
    assert artifacts == [
        ("dotnet-bundle-native_binary", native_disguise),
        ("dotnet-bundle-symbols", symbol_disguise),
    ]
    assert [item["analysis_selection_reason"] for item in report["inventory"]] == [
        "native_runtime_name_content_mismatch_requires_analysis",
        "symbol_type_content_mismatch_requires_analysis",
    ]


def test_native_runtime_structure_is_still_selected_for_bounded_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """既知export構造が一致しても名前偽装余地があるため予算内で解析する。"""

    exports = [
        SimpleNamespace(name=name.encode("ascii"))
        for name in (
            "coreclr_create_delegate",
            "coreclr_execute_assembly",
            "coreclr_initialize",
            "coreclr_shutdown",
        )
    ]
    image = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Characteristics=0x2000),
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(name=b"coreclr.dll", symbols=exports),
        parse_data_directories=lambda **_kwargs: None,
        close=lambda: None,
    )
    monkeypatch.setattr(bundle_unpacker.pefile, "PE", lambda **_kwargs: image)
    runtime = b"MZsynthetic-native-runtime"
    data = _bundle([("coreclr.dll", 2, runtime, False)])

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "recovered"
    assert artifacts == [("dotnet-bundle-native_binary", runtime)]
    item = report["inventory"][0]
    assert item["analysis_selection_reason"] == (
        "native_runtime_structure_consistent_bounded_audit"
    )
    assert item["analysis_content_evidence"]["pe_dll_validated"] is True
    assert item["analysis_content_evidence"]["required_export_profile_matches"] is True


def test_duplicate_content_consumes_one_analysis_budget_slot() -> None:
    """同一bytesの別名entryは一度だけ解析し、budget枯渇を防ぐ。"""

    payload = b"MZsame-payload"
    data = _bundle(
        [
            ("first.dll", 1, payload, False),
            ("second.dll", 1, payload, False),
        ]
    )

    report, artifacts = recover_dotnet_bundle(
        data,
        max_analysis_artifacts=1,
        max_analysis_bytes=len(payload),
    )

    assert report["status"] == "recovered"
    assert artifacts == [("dotnet-bundle-assembly", payload)]
    assert report["analysis_budget"]["candidate_entry_count"] == 2
    assert report["analysis_budget"]["unique_candidate_count"] == 1
    assert report["analysis_budget"]["selection_complete"] is True
    assert report["inventory"][1]["analysis_covered_by_duplicate"] is True


def test_runtime_content_probe_budget_fails_closed_to_analysis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """identity parser予算超過entryは除外せず、未確認として解析対象へ戻す。"""

    monkeypatch.setattr(bundle_unpacker, "MAX_RUNTIME_CONTENT_PROBES", 1)
    first = b"MZfirst-runtime-disguise"
    second = b"MZsecond-runtime-disguise"
    data = _bundle(
        [
            ("System.First.dll", 1, first, False),
            ("System.Second.dll", 1, second, False),
        ]
    )

    report, artifacts = recover_dotnet_bundle(data)

    assert report["status"] == "recovered"
    assert artifacts == [
        ("dotnet-bundle-assembly", first),
        ("dotnet-bundle-assembly", second),
    ]
    budget = report["runtime_content_assessment_budget"]
    assert budget["performed_probe_count"] == 1
    assert budget["omitted_probe_count"] == 1
    assert budget["budget_exhausted"] is True
    assert report["inventory"][1]["analysis_content_evidence"]["status"] == (
        "aggregate_content_probe_budget_exceeded"
    )


def test_runtime_content_per_entry_probe_limit_fails_closed_to_analysis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """単体probe上限超過も台帳から消さず、解析候補とbudget省略へ記録する。"""

    monkeypatch.setattr(bundle_unpacker, "MAX_RUNTIME_CONTENT_PROBE_BYTES", 4)
    payload = b"MZruntime-disguise"
    report, artifacts = recover_dotnet_bundle(
        _bundle([("System.Decoy.dll", 1, payload, False)])
    )

    assert report["status"] == "recovered"
    assert artifacts == [("dotnet-bundle-assembly", payload)]
    budget = report["runtime_content_assessment_budget"]
    assert budget["performed_probe_count"] == 0
    assert budget["per_entry_budget_omitted_probe_count"] == 1
    assert budget["omitted_probe_count"] == 1
    assert budget["budget_exhausted"] is True
    assert report["inventory"][0]["analysis_content_evidence"]["status"] == (
        "content_probe_budget_exceeded"
    )


def test_default_count_budget_reserves_application_and_configuration() -> None:
    """runtime風entryが先行しても末尾のアプリ本体・設定を32件枠へ確保する。"""

    entries = [
        (f"System.Decoy{index}.dll", 1, f"MZdecoy-{index}".encode(), False)
        for index in range(35)
    ]
    app = b"MZapplication"
    config = b"{}"
    entries.extend(
        [
            ("Acme.Tool.dll", 1, app, False),
            ("Acme.Tool.runtimeconfig.json", 4, config, False),
        ]
    )

    report, artifacts = recover_dotnet_bundle(_bundle(entries))

    assert report["status"] == "analysis_budget_partial"
    assert report["analysis_artifact_count"] == 32
    assert ("dotnet-bundle-assembly", app) in artifacts
    assert ("dotnet-bundle-runtime_config_json", config) in artifacts
    assert report["analysis_budget"]["omitted_unique_artifact_count"] == 5
    assert report["analysis_budget"]["selection_complete"] is False


@pytest.mark.parametrize(
    ("kwargs", "error_fragment"),
    [
        ({"max_analysis_artifacts": 33}, "artifact件数"),
        ({"max_analysis_bytes": 128 * 1024 * 1024 + 1}, "byte数"),
        ({"max_analysis_artifacts": True}, "artifact件数"),
    ],
)
def test_analysis_budget_cannot_expand_fixed_cap(
    kwargs: dict[str, object],
    error_fragment: str,
) -> None:
    """呼出側がbundle固有の固定予算を拡張することを拒否する。"""

    report, artifacts = recover_dotnet_bundle(
        _bundle([("sample.dll", 1, b"MZfixture", False)]),
        **kwargs,
    )

    assert report["status"] == "parse_failed"
    assert error_fragment in report["error"]
    assert artifacts == []

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
