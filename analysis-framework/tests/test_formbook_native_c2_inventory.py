"""XLoader builder配置の純粋・非実行分類を人工値だけで検証する。"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
FAMILY = ROOT / "analysis-framework" / "malware" / "formbook_loader"


def _load_module(name: str, filename: str) -> object:
    """検体を読まず、指定したPython sourceだけをテスト用にimportする。"""

    specification = importlib.util.spec_from_file_location(name, FAMILY / filename)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


NATIVE = _load_module("formbook_native_builder_for_inventory_test", "native_xloader.py")
INVENTORY = _load_module("formbook_native_c2_inventory_test", "native_c2_inventory.py")


def _builder(offset: int, value: bytes) -> object:
    """実際のDecodedBuilder型で無害な人工値を作る。"""

    return NATIVE.DecodedBuilder(function_offset=offset, bl_value=0x5A, decoded=value)


def _encoded(label: str) -> bytes:
    """検体や実endpointを含まないcanonical Base64値を作る。"""

    return base64.b64encode(label.encode("ascii"))


def _primary_builders(count: int = 64) -> list[object]:
    """検体固有offsetではない連続した人工clusterを作る。"""

    return [_builder(0x10000 + index * 0x80, _encoded(f"synthetic-primary-{index:03d}")) for index in range(count)]


def _full_fixture() -> list[object]:
    """175 builder、73 canonical候補、64件主clusterの人工系列を作る。"""

    primary = _primary_builders()
    before = [_builder(0x2000 + index * 0x2000, _encoded(f"synthetic-other-{index:03d}")) for index in range(4)]
    after = [_builder(0x20000 + index * 0x2000, _encoded(f"synthetic-other-{index + 4:03d}")) for index in range(5)]
    unrelated = [_builder(0x40000 + index * 0x100, b"not-base64-data") for index in range(102)]
    builders = unrelated + after + primary[::-1] + before
    assert len(builders) == 175
    return builders


def test_175_builders_73_candidates_confirm_only_unique_primary_64() -> None:
    builders = _full_fixture()

    report = INVENTORY.classify_native_c2_inventory(builders)

    assert report["status"] == "primary_pool_confirmed"
    assert report["reason"] == "unique_64_candidate_cluster"
    assert report["builder_count"] == 175
    assert report["base64_candidate_count"] == 73
    assert report["primary_pool_candidate_count"] == 64
    assert report["non_primary_candidate_count"] == 9
    assert report["candidate_set_complete"] is True
    assert report["cluster_evidence"]["largest_cluster_size"] == 64
    assert report["cluster_evidence"]["runner_up_cluster_size"] == 1
    assert report["cluster_evidence"]["dominance_margin"] == 63
    assert (
        report["cluster_evidence"]["observed_minimum_boundary_gap"]
        >= report["cluster_evidence"]["required_boundary_gap"]
    )
    assert report["primary_pool"][0]["function_offset"] == "0x10000"
    assert all(
        set(candidate) == {"function_offset", "length", "sha256", "structural_score"}
        for candidate in report["non_primary_candidates"]
    )
    assert report["safety"]["raw_decoded_values_included"] is False
    published = json.dumps(report, sort_keys=True)
    assert "synthetic-primary" not in published
    assert _encoded("synthetic-primary-000").decode("ascii") not in published
    assert "bootstrap" not in published.lower()


def test_offset_shift_and_input_order_do_not_fix_a_sample_specific_address() -> None:
    builders = _full_fixture()
    shifted = [replace(builder, function_offset=builder.function_offset + 0x190000) for builder in builders]

    first = INVENTORY.classify_native_c2_inventory(builders)
    second = INVENTORY.classify_native_c2_inventory(shifted[::-1])

    assert first["status"] == second["status"] == "primary_pool_confirmed"
    assert [candidate["sha256"] for candidate in first["primary_pool"]] == [
        candidate["sha256"] for candidate in second["primary_pool"]
    ]
    assert first["primary_pool"][0]["function_offset"] != second["primary_pool"][0]["function_offset"]


@pytest.mark.parametrize("count", [63, 65, 66])
def test_nonexact_primary_cluster_never_promoted(count: int) -> None:
    builders = _primary_builders(count)
    builders.append(_builder(0x40000, _encoded("synthetic-other")))

    report = INVENTORY.classify_native_c2_inventory(builders)

    assert report["status"] == "ambiguous"
    assert report["reason"] == "primary_cluster_size_not_64"
    assert report["primary_pool"] == []
    assert report["non_primary_candidate_count"] == count + 1


def test_second_equally_sized_cluster_is_ambiguous() -> None:
    builders = _primary_builders()
    builders += [_builder(0x30000 + index * 0x80, _encoded(f"synthetic-second-{index:03d}")) for index in range(64)]

    report = INVENTORY.classify_native_c2_inventory(builders)

    assert report["status"] == "ambiguous"
    assert report["reason"] == "cluster_margin_insufficient"
    assert report["cluster_evidence"]["dominance_margin"] == 0
    assert report["primary_pool"] == []


def test_runner_up_margin_below_16_is_ambiguous() -> None:
    builders = _primary_builders()
    builders += [_builder(0x30000 + index * 0x80, _encoded(f"synthetic-second-{index:03d}")) for index in range(50)]

    report = INVENTORY.classify_native_c2_inventory(builders)

    assert report["status"] == "ambiguous"
    assert report["cluster_evidence"]["dominance_margin"] == 14
    assert report["primary_pool"] == []


def test_boundary_gap_smaller_than_required_is_ambiguous() -> None:
    builders = _primary_builders()
    builders.append(_builder(0x12280, _encoded("synthetic-nearby")))

    report = INVENTORY.classify_native_c2_inventory(builders)

    assert report["status"] == "ambiguous"
    assert report["reason"] == "cluster_boundary_gap_insufficient"
    assert report["cluster_evidence"]["largest_cluster_size"] == 64
    assert report["primary_pool"] == []


def test_no_neighboring_cluster_leaves_boundary_unobserved() -> None:
    report = INVENTORY.classify_native_c2_inventory(_primary_builders())

    assert report["status"] == "ambiguous"
    assert report["reason"] == "cluster_boundary_unobserved"
    assert report["primary_pool"] == []


def test_noncanonical_base64_and_helper_like_values_are_not_candidates() -> None:
    builders = [
        _builder(0x100, b"QUJDREVG"),
        _builder(0x200, b"AB=="),  # pad bitが非canonical
        _builder(0x300, b"QUJDREVG="),
        _builder(0x400, b"QUJD\nREVG"),
        _builder(0x500, b"api-helper-name"),
    ]

    report = INVENTORY.classify_native_c2_inventory(builders)

    assert report["status"] == "ambiguous"
    assert report["base64_candidate_count"] == 1
    assert report["primary_pool"] == []
    assert report["non_primary_candidates"][0]["sha256"]


@pytest.mark.parametrize("offset", [0, 0x100])
def test_duplicate_offset_is_rejected_even_for_non_candidates(offset: int) -> None:
    report = INVENTORY.classify_native_c2_inventory([_builder(offset, b"not-base64"), _builder(offset, b"QUJDREVG")])

    assert report["status"] == "invalid_input"
    assert report["reason"] == "duplicate_function_offset"
    assert report["candidate_set_complete"] is False
    assert report["primary_pool"] == report["non_primary_candidates"] == []


@pytest.mark.parametrize("offset", [-1, True, 1 << 63])
def test_invalid_offset_is_rejected(offset: int) -> None:
    report = INVENTORY.classify_native_c2_inventory([_builder(offset, b"QUJDREVG")])

    assert report["status"] == "invalid_input"
    assert report["reason"] == "builder_shape_invalid"
    assert report["candidate_set_complete"] is False


def test_invalid_builder_shape_is_rejected_without_partial_inventory() -> None:
    report = INVENTORY.classify_native_c2_inventory([_builder(0x100, b"QUJDREVG"), object()])

    assert report["status"] == "invalid_input"
    assert report["reason"] == "builder_sequence_invalid"
    assert report["primary_pool"] == report["non_primary_candidates"] == []


@pytest.mark.parametrize(
    ("builders", "reason"),
    [
        (
            (_builder(index, b"not-base64") for index in range(4_097)),
            "builder_count_limit",
        ),
        ([_builder(0x100, b"A" * 4_097)], "builder_value_limit"),
        (
            [_builder(index * 0x20, b"QUJDREVG") for index in range(1_025)],
            "candidate_count_limit",
        ),
    ],
)
def test_count_and_value_limits_fail_closed(builders: object, reason: str) -> None:
    report = INVENTORY.classify_native_c2_inventory(builders)

    assert report["status"] == "input_limit_exceeded"
    assert report["reason"] == reason
    assert report["candidate_set_complete"] is False
    assert report["primary_pool"] == report["non_primary_candidates"] == []


def test_total_input_byte_budget_fails_closed() -> None:
    builders = (_builder(index * 0x20, b"!" * 4_096) for index in range(1_025))

    report = INVENTORY.classify_native_c2_inventory(builders)

    assert report["status"] == "input_limit_exceeded"
    assert report["reason"] == "total_value_limit"
    assert report["primary_pool"] == report["non_primary_candidates"] == []
