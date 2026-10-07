"""FormBook／XLoader memory imageの非実行routeを人工byte列で検証する。"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

FRAMEWORK = Path(__file__).parents[1]
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from classifiers.classify_sample import detection_supports_family_attribution
from malware.formbook_loader import detect as detector
from malware.formbook_loader import native_c2_inventory, native_xloader


def _mapped_image(*, entry_rva: int = 0x20000) -> bytes:
    """単一sectionをmemory配置した無害な人工I386 PEを作る。"""

    size = 0x12000
    data = bytearray(size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x14C,
        1,
        0,
        0,
        0,
        0xE0,
        0x0102,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, entry_rva)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, size)
    struct.pack_into("<I", data, optional + 60, 0x1000)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section + 8,
        size - 0x1000,
        0x1000,
        size - 0x1000,
        0x1000,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[0x1000:] = b"\x90" * (size - 0x1000)
    return bytes(data)


def _raw_image() -> bytes:
    """標準x86 frameが十分にある無害なheaderなし人工像を作る。"""

    body = b"\x55\x8b\xec\xc3" * detector.MIN_RAW_X86_FRAME_PROLOGUES
    return body + b"\x90" * (detector.MIN_NATIVE_MEMORY_ROUTE_SIZE - len(body))


def _confirmed_structure() -> dict[str, object]:
    """生値を含まない合成の構造確認結果を返す。"""

    return {
        "status": "confirmed",
        "automation_status": "decoded",
        "key_status": "statically_recovered",
        "call_target_status": "resolved",
        "call_target_selection_method": "dominant",
        "base_key_recovery_status": "recovered",
        "base_key_helper_count": 1,
        "builder_count": 175,
        "seed_inventory_status": "primary_pool_confirmed",
        "canonical_base64_candidate_count": 73,
        "primary_seed_pool_candidate_count": 64,
        "non_primary_candidate_count": 9,
        "raw_values_included": False,
        "key_material_included": False,
    }


def _decoded_native_proof() -> SimpleNamespace:
    """route確認関数用の最小structural proofを返す。"""

    return SimpleNamespace(
        status="decoded",
        key_status="statically_recovered",
        call_target_discovery=SimpleNamespace(
            status="resolved",
            selection_method="dominant",
        ),
        base_key_recovery=SimpleNamespace(
            status="recovered",
            helper_offsets=(0x1234,),
        ),
        builders=tuple(object() for _ in range(175)),
    )


def _confirmed_inventory() -> dict[str, object]:
    """route確認関数用の64件seed pool証拠を返す。"""

    return {
        "status": "primary_pool_confirmed",
        "candidate_set_complete": True,
        "base64_candidate_count": 73,
        "primary_pool_candidate_count": 64,
        "non_primary_candidate_count": 9,
    }


@pytest.mark.parametrize(
    ("sample", "expected_shape"),
    [
        (_mapped_image(), "mapped_i386_pe_memory_image"),
        (_raw_image(), "raw_x86_memory_image"),
    ],
    ids=("mapped-pe", "raw-x86"),
)
def test_strict_memory_shapes_route_only_after_native_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    sample: bytes,
    expected_shape: str,
) -> None:
    """mapped／raw両形式を同じXLoader構造証拠でhandlerへ渡す。"""

    monkeypatch.setattr(
        detector,
        "_confirm_native_xloader_memory_route",
        lambda _data: _confirmed_structure(),
    )

    result = detector.detect(sample, Path("memory.dmp"))

    campaign = next(
        item
        for item in result["campaigns"]
        if item["campaign_type"]
        == "formbook_native_xloader_memory_image_route"
    )
    probe = result["observations"]["native_xloader_memory_image_route"]
    assert probe["status"] == "route_candidate"
    assert probe["shape"] == expected_shape
    assert probe["native_decoder_attempted"] is True
    assert probe["native_structure"]["primary_seed_pool_candidate_count"] == 64
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["c2_confirmed"] is False
    assert probe["sample_executed"] is False
    assert probe["network_contacted"] is False
    assert campaign["supports_family_attribution"] is False
    assert detection_supports_family_attribution(result) is False


def test_memory_shape_without_xloader_proof_is_not_routed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """外形だけではcampaign候補にもfamily証拠にも昇格しない。"""

    rejected = _confirmed_structure()
    rejected["status"] = "not_confirmed"
    rejected["seed_inventory_status"] = "ambiguous"
    rejected["primary_seed_pool_candidate_count"] = 0
    monkeypatch.setattr(
        detector,
        "_confirm_native_xloader_memory_route",
        lambda _data: rejected,
    )

    result = detector.detect(_raw_image(), Path("memory.dmp"))

    assert result["matched"] is False
    probe = result["observations"]["native_xloader_memory_image_route"]
    assert probe["status"] == "structure_not_confirmed"
    assert probe["native_decoder_attempted"] is True
    assert probe["native_structure"]["primary_seed_pool_candidate_count"] == 0


def test_prefilter_rejects_normal_entry_and_sparse_raw_before_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """通常PEとframe数不足rawへ高コストdecoderを呼ばない。"""

    monkeypatch.setattr(
        detector,
        "_confirm_native_xloader_memory_route",
        lambda _data: pytest.fail("shape拒否前にnative decoderが呼ばれました"),
    )

    normal_entry = detector._probe_native_xloader_memory_image(
        _mapped_image(entry_rva=0x1000)
    )
    sparse_raw = detector._probe_native_xloader_memory_image(
        b"\x55\x8b\xec\xc3"
        + b"\x90" * (detector.MIN_NATIVE_MEMORY_ROUTE_SIZE - 4)
    )

    assert normal_entry["status"] == "not_candidate"
    assert normal_entry["entry_outside_image"] is False
    assert normal_entry["native_decoder_attempted"] is False
    assert sparse_raw["status"] == "not_candidate"
    assert sparse_raw["standard_frame_prologue_count"] == 1
    assert sparse_raw["native_decoder_attempted"] is False


def test_mapped_route_requires_all_data_directories_to_be_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """import以外も含むdirectory付きPEをmemory routeへ入れない。"""

    monkeypatch.setattr(
        detector,
        "_confirm_native_xloader_memory_route",
        lambda _data: pytest.fail("directory拒否前にnative decoderが呼ばれました"),
    )
    sample = bytearray(_mapped_image())
    optional = 0x98
    struct.pack_into("<II", sample, optional + 96 + 2 * 8, 0x3000, 0x100)

    probe = detector._probe_native_xloader_memory_image(bytes(sample))

    assert probe["status"] == "not_candidate"
    assert probe["data_directories_absent"] is False
    assert probe["native_decoder_attempted"] is False


def test_native_structure_confirmation_requires_complete_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全structural invariantが揃う場合だけ確認済みにする。"""

    decoded = _decoded_native_proof()
    monkeypatch.setattr(
        native_xloader,
        "auto_decode_stack_string_builders",
        lambda _data: decoded,
    )
    monkeypatch.setattr(
        native_c2_inventory,
        "classify_native_c2_inventory",
        lambda _builders: _confirmed_inventory(),
    )

    result = detector._confirm_native_xloader_memory_route(b"test")

    assert result["status"] == "confirmed"
    assert result["builder_count"] == 175
    assert result["primary_seed_pool_candidate_count"] == 64
    assert result["raw_values_included"] is False
    assert result["key_material_included"] is False


@pytest.mark.parametrize(
    ("proof_change", "inventory_change"),
    [
        ({"status": "analyzed_partial"}, {}),
        ({"key_status": "unresolved"}, {}),
        ({"call_target_status": "ambiguous"}, {}),
        ({"selection_method": "unique"}, {}),
        ({"recovery_status": "ambiguous"}, {}),
        ({"helper_offsets": (0x1234, 0x5678)}, {}),
        ({}, {"status": "ambiguous"}),
        ({}, {"candidate_set_complete": False}),
        ({}, {"primary_pool_candidate_count": 63}),
    ],
)
def test_native_structure_confirmation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    proof_change: dict[str, object],
    inventory_change: dict[str, object],
) -> None:
    """復号・鍵・target・helper・64件poolの欠落を全て拒否する。"""

    decoded = _decoded_native_proof()
    if "status" in proof_change:
        decoded.status = proof_change["status"]
    if "key_status" in proof_change:
        decoded.key_status = proof_change["key_status"]
    if "call_target_status" in proof_change:
        decoded.call_target_discovery.status = proof_change[
            "call_target_status"
        ]
    if "selection_method" in proof_change:
        decoded.call_target_discovery.selection_method = proof_change[
            "selection_method"
        ]
    if "recovery_status" in proof_change:
        decoded.base_key_recovery.status = proof_change["recovery_status"]
    if "helper_offsets" in proof_change:
        decoded.base_key_recovery.helper_offsets = proof_change[
            "helper_offsets"
        ]
    inventory = {**_confirmed_inventory(), **inventory_change}
    monkeypatch.setattr(
        native_xloader,
        "auto_decode_stack_string_builders",
        lambda _data: decoded,
    )
    monkeypatch.setattr(
        native_c2_inventory,
        "classify_native_c2_inventory",
        lambda _builders: inventory,
    )

    result = detector._confirm_native_xloader_memory_route(b"test")

    assert result["status"] == "not_confirmed"
    assert result["raw_values_included"] is False
    assert result["key_material_included"] is False
