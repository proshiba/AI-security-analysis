"""StealC保護外層のexact-hash構造判定を検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from extractors.stealc import extractor


REPOSITORY = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPOSITORY / "analysis-framework" / "common" / "analysis_contract.py"
CONTRACT_SPEC = importlib.util.spec_from_file_location("stealc_analysis_contract", CONTRACT_PATH)
assert CONTRACT_SPEC and CONTRACT_SPEC.loader
contract = importlib.util.module_from_spec(CONTRACT_SPEC)
CONTRACT_SPEC.loader.exec_module(contract)
CLUSTER_PATH = (
    REPOSITORY
    / "analysis-results"
    / "research"
    / "static-analysis"
    / "stealc-taggant-wrapper-cluster-20260815"
    / "cluster.json"
)
REVIEWED_SHA256 = "125382411e94398dd47ef364807868a3d2a6a4d4821d1513897278e77ef005b1"
EXECUTABLE = 0x60000020
NON_EXECUTABLE = 0x40000040


def _section(
    name: str,
    raw_size: int,
    virtual_size: int,
    virtual_address: int,
    raw_offset: int,
    *,
    executable: bool,
) -> SimpleNamespace:
    return SimpleNamespace(
        Name=name.encode("ascii").ljust(8, b" "),
        SizeOfRawData=raw_size,
        Misc_VirtualSize=virtual_size,
        VirtualAddress=virtual_address,
        PointerToRawData=raw_offset,
        Characteristics=EXECUTABLE if executable else NON_EXECUTABLE,
    )


def _wrapper_fixture() -> tuple[bytes, SimpleNamespace]:
    raw_offset = 4096
    sections = []
    definitions = [
        ("", 80_896, 2_347_008, 0x1000, True),
        (".rsrc", 0, 4096, 0x23E000, False),
        (".idata", 512, 4096, 0x23F000, False),
        ("", 512, 2_744_320, 0x240000, True),
        ("oggjeoxe", 1_688_064, 1_691_648, 0x4DE000, True),
        ("bpbnhoje", 1024, 4096, 0x67B000, True),
        (".taggant", 8704, 12_288, 0x67C000, True),
    ]
    for name, raw_size, virtual_size, virtual_address, executable in definitions:
        sections.append(
            _section(
                name,
                raw_size,
                virtual_size,
                virtual_address,
                raw_offset,
                executable=executable,
            )
        )
        raw_offset += raw_size
    directories = [SimpleNamespace(VirtualAddress=0) for _index in range(15)]
    image = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(
            Magic=0x10B,
            DATA_DIRECTORY=directories,
            AddressOfEntryPoint=0x67C000,
            SizeOfHeaders=1024,
        ),
        sections=sections,
    )
    return bytes(raw_offset), image


def _patch_entropy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        extractor,
        "_section_entropy",
        lambda _data, _start, size: 8.0 if size >= 64 * 1024 else 0.0,
    )


def test_reviewed_hashes_and_fingerprint_match_canonical_cluster() -> None:
    cluster = json.loads(CLUSTER_PATH.read_text(encoding="utf-8"))
    assert set(cluster["sample_sha256"]) == extractor.REVIEWED_PROTECTED_WRAPPER_SHA256
    assert (
        cluster["cluster"]["structural_fingerprint_sha256"]
        == extractor.PROTECTED_WRAPPER_FINGERPRINT_SHA256
    )
    assert cluster["cluster"]["id"] == extractor.PROTECTED_WRAPPER_CLUSTER_ID


def test_section_entropy_is_bounded_and_exact_for_uniform_bytes() -> None:
    assert extractor._section_entropy(bytes(range(256)) * 4, 0, 1024) == 8.0
    assert extractor._section_entropy(b"\0" * 32, 0, 32) == 0.0
    assert extractor._section_entropy(b"fixture", 0, 8) is None


def test_exact_reviewed_wrapper_returns_structural_evidence_without_promotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, image = _wrapper_fixture()
    _patch_entropy(monkeypatch)
    profile = extractor._protected_wrapper_profile(data, image, REVIEWED_SHA256)
    assert profile is not None
    assert profile["cluster_id"] == extractor.PROTECTED_WRAPPER_CLUSTER_ID
    assert profile["matched_patterns"] == [
        "reviewed_exact_sha256",
        "x86_pe32_seven_section_layout",
        "randomized_dual_executable_sections",
        "taggant_entrypoint_section",
        "no_overlay",
    ]
    assert profile["observed"]["randomized_section_names"] == ["oggjeoxe", "bpbnhoje"]
    assert profile["protector_exact_version_confirmed"] is False
    assert profile["terminal_family_confirmed_from_wrapper_alone"] is False
    assert profile["terminal_payload_recovered"] is False
    assert profile["static_config_recovered"] is False
    assert profile["c2_recovered"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "unreviewed_hash",
        "wrong_machine",
        "managed_pe",
        "wrong_entrypoint",
        "invalid_random_name",
        "overlay",
        "missing_section",
    ],
)
def test_wrapper_profile_fails_closed_on_contract_mutation(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    data, image = _wrapper_fixture()
    digest = REVIEWED_SHA256
    _patch_entropy(monkeypatch)
    if mutation == "unreviewed_hash":
        digest = "0" * 64
    elif mutation == "wrong_machine":
        image.FILE_HEADER.Machine = 0x8664
    elif mutation == "managed_pe":
        image.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress = 0x1234
    elif mutation == "wrong_entrypoint":
        image.OPTIONAL_HEADER.AddressOfEntryPoint = image.sections[4].VirtualAddress
    elif mutation == "invalid_random_name":
        image.sections[4].Name = b"NOT-RAND"
    elif mutation == "overlay":
        data += b"\0"
    elif mutation == "missing_section":
        image.sections.pop()
    assert extractor._protected_wrapper_profile(data, image, digest) is None


def test_extract_maps_reviewed_wrapper_to_tier_two_only(monkeypatch: pytest.MonkeyPatch) -> None:
    data, image = _wrapper_fixture()
    _patch_entropy(monkeypatch)
    monkeypatch.setattr(extractor, "extract_rc4_profile", lambda _data: None)
    monkeypatch.setattr(extractor, "extract_xor_profile", lambda _data: None)
    monkeypatch.setattr(extractor, "_pe", lambda _data: image)
    monkeypatch.setattr(extractor, "sha256_bytes", lambda _data: REVIEWED_SHA256)

    result = extractor.extract(data, "reviewed-wrapper.exe")
    quality = contract.handler_result_quality(result)
    assert quality["tier"] == 2
    assert quality["tier_name"] == "structural_corroboration"
    assert result["config"]["profile"] is None
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["protected_wrapper"]["reviewed_hash"] is True
    assert result["findings"] == []
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_extract_keeps_unreviewed_wrapper_at_tier_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    data, image = _wrapper_fixture()
    _patch_entropy(monkeypatch)
    monkeypatch.setattr(extractor, "extract_rc4_profile", lambda _data: None)
    monkeypatch.setattr(extractor, "extract_xor_profile", lambda _data: None)
    monkeypatch.setattr(extractor, "_pe", lambda _data: image)
    monkeypatch.setattr(extractor, "sha256_bytes", lambda _data: "0" * 64)

    result = extractor.extract(data, "unreviewed-wrapper.exe")
    assert contract.handler_result_quality(result)["tier"] == 0
    assert result["config"]["protected_wrapper"] is None
