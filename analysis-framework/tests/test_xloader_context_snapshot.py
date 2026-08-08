from __future__ import annotations

import argparse

import pytest

from malware.formbook_loader.context_snapshot import (
    ContextSnapshotError,
    build_report,
    inspect_snapshot,
    parse_snapshot_spec,
)


def _inspect(data: bytes, *, image_base: int = 0) -> dict[str, object]:
    return inspect_snapshot(
        data,
        label="state",
        image_base=image_base,
        module_extent=0x20,
        context_gap=0x10,
        c2_table_pointer_offset=0x14,
        record_width=0x270,
    )


def test_zero_pointer_is_distinguished_from_uncaptured_field() -> None:
    data = bytearray(0x48)
    data[0x30] = 0x41

    report = _inspect(bytes(data))

    assert report["field_captured"] is True
    assert report["c2_table_pointer_status"] == "zero"
    assert report["c2_table_pointer_is_zero"] is True
    assert report["c2_table_pointer_initialized"] is False
    assert report["c2_record_bytes_available"] is False
    assert report["field_page_nonzero_bytes"] == 1
    assert report["pointer_value_published"] is False


def test_pointer_classification_does_not_publish_pointer_value() -> None:
    data = bytearray(0x400)
    data[0x44:0x48] = (0x1020).to_bytes(4, "little")

    report = _inspect(bytes(data), image_base=0x1000)

    assert report["c2_table_pointer_status"] == "inside_snapshot"
    assert report["c2_table_pointer_initialized"] is True
    assert report["c2_record_bytes_available"] is True
    assert "c2_table_pointer_value" not in report


def test_uncaptured_field_is_reported_without_guessing() -> None:
    report = _inspect(bytes(0x40))

    assert report["field_captured"] is False
    assert report["c2_table_pointer_status"] == "not_captured"
    assert report["c2_table_pointer_initialized"] is None
    assert report["c2_record_bytes_available"] is False


def test_pointer_outside_snapshot_does_not_claim_record_bytes() -> None:
    data = bytearray(0x80)
    data[0x44:0x48] = (0x5000).to_bytes(4, "little")

    report = _inspect(bytes(data), image_base=0x1000)

    assert report["c2_table_pointer_status"] == "outside_snapshot"
    assert report["c2_table_pointer_initialized"] is True
    assert report["c2_record_bytes_available"] is False


def test_build_report_compares_multiple_zero_snapshots() -> None:
    first = bytes(0x48)
    second = bytes(0x50)

    report = build_report(
        [("early", first), ("final", second)],
        image_base=0,
        module_extent=0x20,
        context_gap=0x10,
        c2_table_pointer_offset=0x14,
        record_width=0x270,
    )

    assert report["comparison"] == {
        "snapshot_count": 2,
        "all_fields_captured": True,
        "all_c2_table_pointers_zero": True,
        "pointer_status_changed": False,
        "c2_record_bytes_available_snapshot_count": 0,
    }
    assert report["safety"]["absolute_paths_published"] is False
    assert report["safety"]["sample_executed_by_tool"] is False
    assert report["safety"]["source_snapshot_may_derive_from_external_execution"] is True


def test_build_report_rejects_empty_snapshot_list() -> None:
    with pytest.raises(ContextSnapshotError, match="snapshotがありません"):
        build_report(
            [],
            image_base=0,
            module_extent=0x20,
            context_gap=0x10,
            c2_table_pointer_offset=0x14,
            record_width=0x270,
        )


def test_parse_snapshot_spec_rejects_path_like_label() -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_snapshot_spec("bad/label=C:/private/state.bin")
