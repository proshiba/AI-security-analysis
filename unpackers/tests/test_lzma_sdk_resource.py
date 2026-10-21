from __future__ import annotations

import lzma
import struct
from types import SimpleNamespace

import pytest

from unpackers import lzma_sdk_resource as lzma_sdk_resource_module
from unpackers import static_unpacker as static_unpacker_module
from unpackers.lzma_sdk_resource import (
    LzmaSdkResourceScanner,
    has_lzma_sdk_resource_prefix,
)
from unpackers.static_unpacker import pe_summary


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _minimal_pe() -> bytes:
    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 20, 0x1000)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(optional), 0x210E)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        1,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80 : 0x80 + 24 + len(optional) + len(section)] = (
        b"PE\0\0" + coff + optional + section
    )
    image[0x200] = 0xC3
    return bytes(image)


def _resource(payload: bytes, *, dictionary_size: int = 1 << 20) -> bytes:
    lc, lp, pb = 3, 0, 2
    property_byte = (pb * 5 + lp) * 9 + lc
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": dictionary_size,
            "lc": lc,
            "lp": lp,
            "pb": pb,
        }
    ]
    compressed = lzma.compress(payload, format=lzma.FORMAT_RAW, filters=filters)
    properties = bytes((property_byte,)) + struct.pack("<I", dictionary_size)
    return (
        struct.pack("<I", len(properties))
        + properties
        + struct.pack("<I", len(payload))
        + compressed
    )


def _outer_pe_with_resource(resource: bytes) -> bytes:
    resource_body_offset = 0x60
    resource_virtual_size = resource_body_offset + len(resource)
    resource_raw_size = _align(resource_virtual_size, 0x200)
    resource_tree = bytearray(resource_raw_size)
    struct.pack_into("<IIHHHH", resource_tree, 0, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", resource_tree, 16, 10, 0x80000018)
    struct.pack_into("<IIHHHH", resource_tree, 0x18, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", resource_tree, 0x28, 1, 0x80000030)
    struct.pack_into("<IIHHHH", resource_tree, 0x30, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", resource_tree, 0x40, 1033, 0x48)
    struct.pack_into(
        "<IIII",
        resource_tree,
        0x48,
        0x2000 + resource_body_offset,
        len(resource),
        0,
        0,
    )
    resource_tree[resource_body_offset : resource_body_offset + len(resource)] = (
        resource
    )

    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 20, 0x1000)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x3000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)
    struct.pack_into("<II", optional, 112, 0x2000, resource_virtual_size)
    coff = struct.pack("<HHIIIHH", 0x14C, 2, 0, 0, 0, len(optional), 0x210E)
    text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        1,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    rsrc = struct.pack(
        "<8sIIIIIIHHI",
        b".rsrc\0\0\0",
        resource_virtual_size,
        0x2000,
        resource_raw_size,
        0x400,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    image = bytearray(0x400 + resource_raw_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    headers = b"PE\0\0" + coff + optional + text + rsrc
    image[0x80 : 0x80 + len(headers)] = headers
    image[0x200] = 0xC3
    image[0x400:] = resource_tree
    return bytes(image)


def test_valid_resource_recovers_strict_pe_without_family_promotion() -> None:
    payload = _minimal_pe()
    scanner = LzmaSdkResourceScanner()
    assert scanner.inspect(_resource(payload)) is True
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == [payload]
    assert report["status"] == "recovered_terminal_pe"
    assert report["candidate_set_complete"] is True
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False


def test_prefix_requires_exact_five_byte_property_block() -> None:
    valid = _resource(_minimal_pe())
    assert has_lzma_sdk_resource_prefix(valid) is True
    assert has_lzma_sdk_resource_prefix(struct.pack("<I", 4) + valid[4:]) is False
    assert has_lzma_sdk_resource_prefix(valid[:13]) is False


@pytest.mark.parametrize("suffix", [b"\0", b"trailing"])
def test_unused_trailing_data_is_rejected(suffix: bytes) -> None:
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(_resource(_minimal_pe()) + suffix)
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["status"] == "candidate_rejected"
    assert report["rejection_reasons"] == {"lzma_trailing_data": 1}


def test_truncated_stream_requires_lzma_eof() -> None:
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(_resource(_minimal_pe())[:-1])
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["status"] == "candidate_rejected"
    assert set(report["rejection_reasons"]) <= {
        "lzma_decode_failed",
        "lzma_eof_missing",
        "declared_output_size_mismatch",
    }


@pytest.mark.parametrize("delta", [-1, 1])
def test_declared_output_size_must_match_exactly(delta: int) -> None:
    encoded = bytearray(_resource(_minimal_pe()))
    expected = struct.unpack_from("<I", encoded, 9)[0]
    struct.pack_into("<I", encoded, 9, expected + delta)
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(bytes(encoded))
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["status"] == "candidate_rejected"
    assert report["rejection_reasons"] == {"declared_output_size_mismatch": 1}


def test_invalid_lzma_properties_are_rejected_before_decode() -> None:
    encoded = bytearray(_resource(_minimal_pe()))
    encoded[4] = 225
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(bytes(encoded))
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["rejection_reasons"] == {"properties_invalid": 1}
    assert report["evaluated_candidate_count"] == 0


def test_undersized_dictionary_is_rejected_as_malformed_before_decode() -> None:
    encoded = bytearray(_resource(_minimal_pe()))
    struct.pack_into("<I", encoded, 5, 4095)
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(bytes(encoded))
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["status"] == "candidate_rejected"
    assert report["rejection_reasons"] == {"dictionary_size_invalid": 1}
    assert report["evaluated_candidate_count"] == 0


@pytest.mark.parametrize(
    ("constant_name", "limit_value", "reason"),
    (
        (
            "MAX_RESOURCE_SIZE",
            lambda encoded, _payload: len(encoded) - 1,
            "resource_size_limit",
        ),
        (
            "MAX_OUTPUT_SIZE",
            lambda _encoded, payload: len(payload) - 1,
            "declared_output_size_limit",
        ),
        (
            "MAX_DICTIONARY_SIZE",
            lambda _encoded, _payload: (1 << 20) - 1,
            "dictionary_size_limit",
        ),
        (
            "MAX_COMPRESSION_RATIO",
            lambda _encoded, _payload: 0.5,
            "compression_ratio_limit",
        ),
    ),
)
def test_per_candidate_budget_limit_discards_earlier_valid_result(
    monkeypatch: pytest.MonkeyPatch,
    constant_name: str,
    limit_value,
    reason: str,
) -> None:
    """後続候補の個別上限超過でも、先行する部分成果を返さない。"""

    payload = _minimal_pe()
    encoded = _resource(payload)
    scanner = LzmaSdkResourceScanner()
    assert scanner.inspect(encoded) is True
    monkeypatch.setattr(
        lzma_sdk_resource_module,
        constant_name,
        limit_value(encoded, payload),
    )
    assert scanner.inspect(encoded) is True

    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["status"] == "budget_exhausted"
    assert report["limit_reason"] == reason
    assert report["candidate_count"] == 2
    assert report["recovered_artifact_count"] == 0
    assert report["candidate_set_complete"] is False
    assert report["recovery_attempts_complete"] is False
    assert report["rejection_reasons"] == {}


def test_decoded_non_pe_is_rejected() -> None:
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(_resource(b"not-a-portable-executable"))
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["rejection_reasons"] == {"pe_dos_header_out_of_bounds": 1}


def test_structurally_invalid_section_count_is_rejected() -> None:
    payload = bytearray(_minimal_pe())
    struct.pack_into("<H", payload, 0x80 + 6, 97)
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(_resource(bytes(payload)))
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["rejection_reasons"] == {"pe_section_count_out_of_bounds": 1}


def test_virtual_section_extent_must_fit_size_of_image() -> None:
    payload = bytearray(_minimal_pe())
    section_offset = 0x80 + 24 + 0xE0
    struct.pack_into("<I", payload, section_offset + 8, 0x2000)
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(_resource(bytes(payload)))
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["rejection_reasons"] == {"pe_section_virtual_bounds_invalid": 1}


def test_overlapping_file_backed_sections_are_rejected() -> None:
    payload = bytearray(_minimal_pe())
    pe_offset = 0x80
    optional_size = 0xE0
    section_offset = pe_offset + 24 + optional_size
    struct.pack_into("<H", payload, pe_offset + 6, 2)
    second = struct.pack(
        "<8sIIIIIIHHI",
        b".dup\0\0\0\0",
        1,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    payload[section_offset + 40 : section_offset + 80] = second
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(_resource(bytes(payload)))
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["rejection_reasons"] == {"pe_section_file_ranges_overlap": 1}


def test_candidate_count_limit_discards_earlier_valid_result() -> None:
    encoded = _resource(_minimal_pe())
    scanner = LzmaSdkResourceScanner(max_candidates=1)
    scanner.inspect(encoded)
    scanner.inspect(encoded)
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["status"] == "budget_exhausted"
    assert report["limit_reason"] == "candidate_count_limit"
    assert report["candidate_set_complete"] is False


def test_total_output_limit_blocks_decode_and_returns_no_prefix_result() -> None:
    payload = _minimal_pe()
    scanner = LzmaSdkResourceScanner(max_total_output_size=len(payload) - 1)
    scanner.inspect(_resource(payload))
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["status"] == "budget_exhausted"
    assert report["limit_reason"] == "total_output_size_limit"
    assert report["evaluated_candidate_count"] == 0


def test_total_work_limit_blocks_decode() -> None:
    payload = _minimal_pe()
    encoded = _resource(payload)
    compressed_size = len(encoded) - 13
    scanner = LzmaSdkResourceScanner(
        max_total_work_size=compressed_size + len(payload) - 1
    )
    scanner.inspect(encoded)
    report, recovered = scanner.finalize(resource_inventory_complete=True)

    assert recovered == []
    assert report["status"] == "budget_exhausted"
    assert report["limit_reason"] == "total_work_size_limit"
    assert report["evaluated_candidate_count"] == 0


def test_incomplete_resource_inventory_discards_validated_result() -> None:
    scanner = LzmaSdkResourceScanner()
    scanner.inspect(_resource(_minimal_pe()))
    report, recovered = scanner.finalize(resource_inventory_complete=False)

    assert recovered == []
    assert report["status"] == "resource_inventory_incomplete"
    assert report["candidate_set_complete"] is False

    repeated_report, repeated_recovered = scanner.finalize(
        resource_inventory_complete=True
    )
    assert repeated_recovered == []
    assert repeated_report["status"] == "resource_inventory_incomplete"


def test_static_unpacker_hook_recovers_artifact_from_native_resource() -> None:
    payload = _minimal_pe()
    summary, artifacts = pe_summary(_outer_pe_with_resource(_resource(payload)))

    assert ("pe-resource-lzma-sdk-pe", payload) in artifacts
    lzma_report = summary["lzma_sdk_resource"]
    assert lzma_report["status"] == "recovered_terminal_pe"
    assert lzma_report["recovered_artifact_count"] == 1


def test_static_unpacker_short_resource_read_discards_earlier_lzma_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """宣言sizeより短いresource読取りはinventory不完全として部分成果を破棄する。"""

    payload = _minimal_pe()
    encoded = _resource(payload)
    candidates = [
        static_unpacker_module._PeResourceCandidate(
            data_struct=SimpleNamespace(Size=len(encoded), OffsetToData=0x5000),
            custom_named_type=False,
            named_ui_type=False,
            priority=1,
            ordinal=1,
        ),
        static_unpacker_module._PeResourceCandidate(
            data_struct=SimpleNamespace(Size=len(encoded), OffsetToData=0x6000),
            custom_named_type=False,
            named_ui_type=False,
            priority=1,
            ordinal=2,
        ),
    ]
    monkeypatch.setattr(
        static_unpacker_module,
        "_prioritize_pe_resource_entries",
        lambda _pe: (candidates, 2, False, 0),
    )
    original_get_data = static_unpacker_module.pefile.PE.get_data

    def short_second_resource(self, rva=0, length=None):
        if rva == 0x5000:
            return encoded
        if rva == 0x6000:
            return encoded[:-1]
        return original_get_data(self, rva, length)

    monkeypatch.setattr(
        static_unpacker_module.pefile.PE,
        "get_data",
        short_second_resource,
    )

    summary, artifacts = pe_summary(_outer_pe_with_resource(encoded))

    assert not any(kind == "pe-resource-lzma-sdk-pe" for kind, _blob in artifacts)
    lzma_report = summary["lzma_sdk_resource"]
    assert lzma_report["status"] == "resource_inventory_incomplete"
    assert lzma_report["candidate_count"] == 1
    assert lzma_report["evaluated_candidate_count"] == 1
    assert lzma_report["recovered_artifact_count"] == 0
    assert lzma_report["candidate_set_complete"] is False
    resource_scan = summary["resource_scan"]
    assert resource_scan["status"] == "partial"
    assert resource_scan["invalid_data_entries"] == 1
    assert "resource_data_short_read" in resource_scan["exhausted_reasons"]
