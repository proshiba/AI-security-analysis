"""importless native PEの有界なentry解析を検証する。"""

from __future__ import annotations

import struct

import pytest

from unpackers import opaque_native_entry as opaque
from unpackers import static_unpacker


def _call(site: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (site + 5))


def _minimal_pe64(code_by_rva: dict[int, bytes]) -> bytes:
    data = bytearray(0x1400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 4, 0x1200)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x3000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1200, 0x1000, 0x1200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    for rva, code in code_by_rva.items():
        offset = 0x200 + rva - 0x1000
        data[offset : offset + len(code)] = code
    return bytes(data)


def _resolver_fixture() -> bytes:
    entry = bytearray()
    for value in (0x982F35CB, 0x686804EB):
        site = 0x1000 + len(entry) + 5
        entry.extend(b"\xb9" + struct.pack("<I", value))
        entry.extend(_call(site, 0x1100))
    for value in (0x531226AD, 0x8F598297, 0xDEADBEEF):
        site = 0x1000 + len(entry) + 5
        entry.extend(b"\xba" + struct.pack("<I", value))
        entry.extend(_call(site, 0x1400))
    entry.extend(b"\xc3")

    module_resolver = _call(0x1100, 0x1200) + _call(0x1105, 0x1300) + b"\xc3"
    peb_helper = b"\x65\x48\x8b\x04\x25\x30\x00\x00\x00\xc3"
    hash_function = (
        b"\xb8\x79\x8f\xd5\x52"
        b"\x32\x01"
        b"\x69\xc0\x97\x06\x00\x01"
        b"\x48\xff\xc1"
        b"\x80\x39\x00"
        b"\x75\xf0"
        b"\xc3"
    )
    export_resolver = (
        b"\x66\x81\x39\x4d\x5a"
        b"\x81\x79\x04\x50\x45\x00\x00" + _call(0x140C, 0x1300) + b"\xc3"
    )
    return _minimal_pe64(
        {
            0x1000: bytes(entry),
            0x1100: module_resolver,
            0x1200: peb_helper,
            0x1300: hash_function,
            0x1400: export_resolver,
        }
    )


def test_hash_ascii_name_reproduces_observed_variant() -> None:
    assert (
        opaque.hash_ascii_name("GetProcAddress", seed=0x52D58F79, prime=0x01000697)
        == 0x531226AD
    )
    with pytest.raises(ValueError):
        opaque.hash_ascii_name("非ASCII", seed=1, prime=3)


def test_detects_one_hop_peb_and_export_resolvers_without_execution() -> None:
    result = opaque.analyze_opaque_native_pe(
        _resolver_fixture(),
        max_instructions=20_000,
        max_callsites=128,
        max_candidates=32,
    )

    assert result["status"] == "analyzed_partial"
    assert result["coverage_complete"] is True
    assert result["semantic_resolution_complete"] is False
    assert result["complete"] is False
    assert result["executed"] is False
    assert result["emulated"] is False
    assert result["network_contacted"] is False
    assert result["coverage_complete"] is True
    assert all(
        item["truncated"] is False
        for name, item in result["coverage"].items()
        if name not in {"functions", "hash_values"}
    )
    assert result["coverage"]["functions"]["budget_exhausted"] == 0
    assert result["coverage"]["hash_values"]["api"]["truncated"] is False
    assert result["coverage"]["hash_values"]["module"]["truncated"] is False
    assert result["hash_functions"] == [
        {
            "rva": "0x1300",
            "seed": "0x52d58f79",
            "prime": "0x1000697",
            "algorithm": "fnv1a_like_32",
            "confidence": "high",
        }
    ]
    kinds = {item["kind"]: item for item in result["resolvers"]}
    assert kinds["peb_module_hash_resolver"]["peb_helper_rvas"] == ["0x1200"]
    assert kinds["peb_module_hash_resolver"]["hash_argument_register"] == "rcx"
    assert kinds["pe_export_hash_resolver"]["hash_argument_register"] == "rdx"
    modules = {item["hash"]: item for item in result["module_hash_matches"]}
    assert modules["0x982f35cb"]["matches"] == ["ntdll.dll"]
    assert modules["0x686804eb"]["matches"] == ["kernel32.dll"]
    apis = {item["hash"]: item for item in result["api_hash_matches"]["values"]}
    assert apis["0x531226ad"]["matches"][0]["name"] == "GetProcAddress"
    assert apis["0x8f598297"]["matches"][0]["name"] == "LoadLibraryA"
    assert apis["0xdeadbeef"]["match_status"] == "unresolved"
    assert apis["0xdeadbeef"]["matches"] == []


def test_fail_closed_for_budget_and_non_applicable_pe() -> None:
    limited = opaque.analyze_opaque_native_pe(_resolver_fixture(), max_input_bytes=32)
    assert limited["status"] == "input_budget_exceeded"
    assert limited["complete"] is False
    with pytest.raises(ValueError):
        opaque.analyze_opaque_native_pe(b"MZ", max_candidates=0)
    executable_limited = opaque.analyze_opaque_native_pe(
        _resolver_fixture(), max_executable_bytes=1
    )
    assert executable_limited["status"] == "executable_byte_budget_exceeded"
    assert executable_limited["complete"] is False


def test_missing_dependency_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(opaque, "capstone", None)
    result = opaque.analyze_opaque_native_pe(_resolver_fixture())
    assert result["status"] == "dependency_unavailable"
    assert result["complete"] is False
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_static_unpacker_routes_only_confirmed_importless_native_pe() -> None:
    base = {
        "imports": 0,
        "is_dotnet": False,
        "is_go": False,
        "analysis_coverage": {"imports_known": True},
    }
    assert static_unpacker.should_analyze_opaque_native_entry(base) is True
    assert (
        static_unpacker.should_analyze_opaque_native_entry({**base, "imports": None})
        is False
    )
    assert (
        static_unpacker.should_analyze_opaque_native_entry({**base, "is_dotnet": True})
        is False
    )
    assert (
        static_unpacker.should_analyze_opaque_native_entry(
            {
                **base,
                "analysis_coverage": {"imports_known": False},
            }
        )
        is False
    )


def test_static_unpacker_does_not_promote_coverage_to_semantic_completion() -> None:
    report, _artifacts = static_unpacker.unpack_bytes(
        _resolver_fixture(), "importless-fixture.exe"
    )

    opaque_report = report["opaque_native_entry"]
    assert opaque_report["coverage_complete"] is True
    assert opaque_report["semantic_resolution_complete"] is False
    assert opaque_report["complete"] is False


@pytest.mark.parametrize("directory_count", [0, 1])
def test_short_data_directory_fails_closed_without_index_error(
    directory_count: int,
) -> None:
    sample = bytearray(_resolver_fixture())
    struct.pack_into("<I", sample, 0x98 + 108, directory_count)

    result = opaque.analyze_opaque_native_pe(bytes(sample))

    assert result["status"] in {"analyzed_partial", "partial"}
    assert result["pe"]["is_dotnet"] is False
    assert result["complete"] is False


def test_function_scan_stops_at_ret_before_decoy_fnv_bytes() -> None:
    sample = bytearray(_resolver_fixture())
    hash_offset = 0x200 + 0x1300 - 0x1000
    sample[hash_offset] = 0xC3

    result = opaque.analyze_opaque_native_pe(bytes(sample))

    assert result["hash_functions"] == []
    function = next(item for item in result["functions"] if item["rva"] == "0x1300")
    assert function["termination"] == "ret"
    assert function["fnv_like"] == []


def test_candidate_and_function_budget_cutoffs_are_reported() -> None:
    result = opaque.analyze_opaque_native_pe(_resolver_fixture(), max_candidates=1)

    assert result["coverage_complete"] is False
    assert result["coverage"]["candidate_targets"] == {
        "total": 2,
        "returned": 0,
        "truncated": True,
    }
    assert result["coverage"]["functions"]["total"] > 1
    assert result["coverage"]["functions"]["returned"] == 1
    assert result["coverage"]["functions"]["truncated"] is True


def test_function_instruction_budget_is_not_reported_as_analyzed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(opaque, "DEFAULT_MAX_FUNCTION_INSTRUCTIONS", 1)

    result = opaque.analyze_opaque_native_pe(_resolver_fixture())

    assert result["coverage_complete"] is False
    assert result["coverage"]["functions"]["budget_exhausted"] > 0
    assert any(item["status"] == "budget_exhausted" for item in result["functions"])


def test_entry_cfg_budget_is_part_of_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = _minimal_pe64({0x1000: b"\x75\x01\xc3\xc3"})
    monkeypatch.setattr(opaque, "DEFAULT_ENTRY_CFG_BLOCKS", 1)

    result = opaque.analyze_opaque_native_pe(sample)

    assert result["entry_control_flow"]["budget_exhausted"] is True
    assert result["coverage"]["entry_control_flow"]["truncated"] is True
    assert result["coverage_complete"] is False


def test_public_callsite_and_hash_caps_are_applied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(opaque, "MAX_PUBLIC_CALLSITES", 1)
    monkeypatch.setattr(opaque, "MAX_HASH_VALUES", 1)

    result = opaque.analyze_opaque_native_pe(_resolver_fixture())

    assert result["coverage"]["resolver_callsites"] == {
        "total": 5,
        "returned": 1,
        "truncated": True,
    }
    assert len(result["resolver_callsites"]) == 1
    assert result["coverage"]["hash_values"]["api"] == {
        "total": 3,
        "returned": 1,
        "truncated": True,
    }
    assert result["coverage"]["hash_values"]["module"] == {
        "total": 2,
        "returned": 1,
        "truncated": True,
    }
    assert len(result["api_hash_matches"]["values"]) == 1
    assert len(result["module_hash_matches"]) == 1
    assert result["coverage_complete"] is False


def test_transform_loop_output_cap_is_part_of_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = bytearray()
    for value in (0x10001, 0x10002):
        site = 0x1000 + len(entry) + 5
        entry.extend(b"\xb9" + struct.pack("<I", value))
        entry.extend(_call(site, 0x1100))
    entry.extend(b"\xc3")
    loop = (
        b"\x88\x08\x31\xc0\x83\xc0\x01\x83\xe8\x01\x31\xdb\x31\xc9\x31\xd2\x75\xee\xc3"
    )
    sample = _minimal_pe64({0x1000: bytes(entry), 0x1100: loop})
    monkeypatch.setattr(opaque, "MAX_PUBLIC_LOOP_CANDIDATES", 0)

    result = opaque.analyze_opaque_native_pe(sample)

    assert result["coverage"]["transform_loop_candidates"] == {
        "total": 1,
        "returned": 0,
        "truncated": True,
    }
    assert result["transform_loop_candidates"] == []
    assert result["coverage_complete"] is False
