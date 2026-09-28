"""本物のPEを使わず、immutable bytesとSimpleNamespaceだけで境界を試験する。"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from unpackers.tests.test_managed_resource_consumers_portable import ROOT as RESOURCE_ROOT, RESOURCE_NAMESPACE
import importlib
resources = importlib.import_module(RESOURCE_NAMESPACE + ".managed_resources")


def resource_view_table(rows=()):
    rows = list(rows)
    return NS(num_rows=len(rows), rows=rows)


def resource_view_row(name="synthetic_resource", offset=0, implementation=None):
    return NS(Name=name, Offset=offset, Implementation=implementation)


def resource_view_record(body=b"abc"):
    return len(body).to_bytes(4, "little") + body


def resource_view_fixture(records=None, content=None, *, directory_size=None, directory_rva=None, extra_tables=None):
    content = resource_view_record() if content is None else content
    records = [resource_view_row()] if records is None else records
    data = bytes(128) + content + bytes(128)
    metadata = NS(**{name: resource_view_table() for name in resources.TABLE_NAMES})
    metadata.ManifestResource = resource_view_table(records)
    for name, value in (extra_tables or {}).items():
        setattr(metadata, name, value)
    size = len(content) if directory_size is None else directory_size
    rva = (0x1000 if size else 0) if directory_rva is None else directory_rva
    pe = NS(net=NS(mdtables=metadata, struct=NS(ResourcesRva=rva, ResourcesSize=size)),
            sections=[NS(VirtualAddress=0x1000, SizeOfRawData=len(content), PointerToRawData=128)],
            FILE_HEADER=NS(NumberOfSections=1))
    return data, pe


def resource_view_scan(data, pe, **limits):
    return resources.describe_clr_resources(data, pe, **limits)


def resource_assert_partial(result, reason=None):
    coverage = result.coverage()
    assert coverage["status"] == "partial"
    assert coverage["inventory_complete"] is False
    assert coverage["embedded_scan_complete"] is False
    assert result._descriptors == ()
    assert coverage["counts"]["descriptors_retained"] == 0
    assert set(coverage["reason_counts"]) <= resources.REASONS
    if reason:
        assert reason in coverage["reason_counts"]


def test_resource_portable_normal_embedded_span_and_independent_public_copy():
    data, pe = resource_view_fixture()
    result = resource_view_scan(data, pe)
    coverage = result.coverage()
    assert coverage["status"] == "complete"
    assert coverage["counts"]["validated_resource_bytes"] == 3
    assert coverage["work"]["unique_rows_reserved"] == 1
    assert coverage["work"]["snapshot_row_visits_this_call"] == 1
    descriptor, = result._descriptors
    assert data[descriptor.body_offset:descriptor.body_offset + descriptor.body_size] == b"abc"
    coverage["reason_counts"]["arbitrary"] = 1
    coverage["tables"]["ManifestResource"]["declared"] = 100
    assert result.coverage()["reason_counts"] == {}
    assert result.coverage()["tables"]["ManifestResource"]["declared"] == 1


@pytest.mark.parametrize("body", [b"", b"x", bytes(100)])
def test_resource_portable_body_boundary_exactly_matches_directory(body):
    data, pe = resource_view_fixture(content=resource_view_record(body))
    result = resource_view_scan(data, pe)
    assert result.coverage()["inventory_complete"] is True
    assert result._descriptors[0].body_size == len(body)


def test_resource_portable_absent_table_and_validated_empty_are_distinct():
    data, pe = resource_view_fixture(records=[], content=b"")
    empty = resource_view_scan(data, pe).coverage()
    pe.net.mdtables.ManifestResource = None
    absent = resource_view_scan(data, pe).coverage()
    assert empty["inventory_complete"] is absent["inventory_complete"] is True
    assert empty["tables"]["ManifestResource"]["declared_status"] == "valid"
    assert absent["tables"]["ManifestResource"]["declared_status"] == "absent"
    pe.net.struct.ResourcesRva, pe.net.struct.ResourcesSize = 0x1000, 4
    resource_assert_partial(resource_view_scan(data, pe), "manifest_table_absent_with_directory")


@pytest.mark.parametrize("scope", ["File", "AssemblyRef"])
def test_resource_portable_linked_reference_is_not_embedded_and_does_not_fetch_content(scope):
    linked_table = resource_view_table([NS(Name="PRIVATE_LINK_TARGET")])
    reference = NS(table=linked_table, row_index=1, row=None)
    data, pe = resource_view_fixture(records=[resource_view_row(implementation=reference)], content=b"",
                       extra_tables={scope: linked_table})
    result = resource_view_scan(data, pe)
    assert result.coverage()["inventory_complete"] is True
    assert result.coverage()["external_contents_resolved"] is False
    assert result.coverage()["counts"]["linked_resources"] == 1
    assert result.coverage()["work"]["unique_rows_reserved"] == 2
    assert result._descriptors[0].kind == "linked"
    assert result._descriptors[0].body_offset is None


@pytest.mark.parametrize("scope,rid,foreign,reason", [
    ("File", 0, False, "linked_reference_rid_invalid"),
    ("File", True, False, "linked_reference_rid_invalid"),
    ("File", 2, False, "linked_reference_rid_invalid"),
    ("AssemblyRef", -1, False, "linked_reference_rid_invalid"),
    ("File", 1, True, "linked_reference_foreign_table"),
    ("ExportedType", 1, False, "linked_reference_unsupported"),
])
def test_resource_portable_linked_invalid_scope_or_rid(scope, rid, foreign, reason):
    target = resource_view_table([NS()])
    reference = NS(table=resource_view_table([NS()]) if foreign else target, row_index=rid)
    data, pe = resource_view_fixture(records=[resource_view_row(implementation=reference)], content=b"", extra_tables={scope: target})
    resource_assert_partial(resource_view_scan(data, pe), reason)


def test_resource_portable_unknown_coded_tag_is_not_treated_as_embedded():
    data, pe = resource_view_fixture(records=[resource_view_row(implementation=NS(table=None, row_index=1, tag=3))])
    resource_assert_partial(resource_view_scan(data, pe), "linked_reference_foreign_table")


@pytest.mark.parametrize("name", [None, 123, "", "x" * 513, "a\n", NS(value=123)])
def test_resource_portable_invalid_name_is_never_stringified(name):
    data, pe = resource_view_fixture(records=[resource_view_row(name=name)])
    resource_assert_partial(resource_view_scan(data, pe), "resource_name_invalid")


def test_resource_portable_bounded_heap_string_wrapper_is_supported_privately():
    data, pe = resource_view_fixture(records=[resource_view_row(name=NS(value="PRIVATE_HEAP_NAME"))])
    result = resource_view_scan(data, pe)
    assert result.coverage()["inventory_complete"] is True
    assert result._descriptors[0].name == "PRIVATE_HEAP_NAME"
    assert "PRIVATE_HEAP_NAME" not in json.dumps(result.coverage())


@pytest.mark.parametrize("field", ["ResourcesRva", "ResourcesSize"])
@pytest.mark.parametrize("value", [-1, True, 1 << 32, "4"])
def test_resource_portable_directory_uint32_fields(field, value):
    data, pe = resource_view_fixture()
    setattr(pe.net.struct, field, value)
    resource_assert_partial(resource_view_scan(data, pe), "directory_fields_invalid")


@pytest.mark.parametrize("rva,size,reason", [
    (0, 4, "directory_pair_inconsistent"),
    (0x1000, 0, "directory_pair_inconsistent"),
    ((1 << 32) - 2, 4, "directory_rva_overflow"),
])
def test_resource_portable_directory_pair_and_overflow(rva, size, reason):
    data, pe = resource_view_fixture()
    pe.net.struct.ResourcesRva, pe.net.struct.ResourcesSize = rva, size
    resource_assert_partial(resource_view_scan(data, pe), reason)


@pytest.mark.parametrize("offset", [-1, True, 1 << 32, "0"])
def test_resource_portable_offset_uint32(offset):
    data, pe = resource_view_fixture(records=[resource_view_row(offset=offset)])
    resource_assert_partial(resource_view_scan(data, pe), "resource_offset_invalid")


def test_resource_portable_header_and_body_are_bounded_by_directory_not_only_input_file():
    data, pe = resource_view_fixture(directory_size=3)
    resource_assert_partial(resource_view_scan(data, pe), "resource_header_outside_directory")
    data, pe = resource_view_fixture(directory_size=6)
    assert len(data) > 7
    resource_assert_partial(resource_view_scan(data, pe), "resource_body_outside_directory")
    data, pe = resource_view_fixture(content=b"", records=[resource_view_row()])
    resource_assert_partial(resource_view_scan(data, pe), "embedded_resource_without_directory")


@pytest.mark.parametrize("name", ["TypeRef", "ManifestResource", "File", "AssemblyRef"])
@pytest.mark.parametrize("declared", [None, -1, True, "1", 0, 2])
def test_resource_portable_declared_metadata_mismatch_or_type_is_partial(name, declared):
    data, pe = resource_view_fixture(extra_tables={name: resource_view_table([resource_view_row()] if name == "ManifestResource" else [NS()])})
    getattr(pe.net.mdtables, name).num_rows = declared
    result = resource_view_scan(data, pe)
    resource_assert_partial(result)
    state = result.coverage()["tables"][name]
    assert state["declared_status"] != "valid" or state["row_count_mismatch"]


def test_resource_portable_unsized_rows_are_not_iterated():
    data, pe = resource_view_fixture()
    pe.net.mdtables.ManifestResource.rows = iter([resource_view_row()])
    resource_assert_partial(resource_view_scan(data, pe), "metadata_rows_container_unsupported")


@pytest.mark.parametrize("mutate,reason", [
    ("count_zero", "section_count_invalid"),
    ("count_mismatch", "section_count_mismatch"),
    ("virtual_only", "directory_not_uniquely_file_backed"),
    ("file_truncated", "section_file_bounds_invalid"),
    ("bad_field", "section_fields_invalid"),
    ("rva_overflow", "section_rva_overflow"),
])
def test_resource_portable_section_structural_bounds(mutate, reason):
    data, pe = resource_view_fixture()
    if mutate == "count_zero":
        pe.FILE_HEADER.NumberOfSections = 0
    elif mutate == "count_mismatch":
        pe.FILE_HEADER.NumberOfSections = 2
    elif mutate == "virtual_only":
        pe.sections[0].SizeOfRawData = 0
        pe.sections[0].Misc_VirtualSize = 1024
    elif mutate == "file_truncated":
        pe.sections[0].SizeOfRawData = len(data)
    elif mutate == "bad_field":
        pe.sections[0].PointerToRawData = True
    else:
        pe.sections[0].VirtualAddress = (1 << 32) - 4
    resource_assert_partial(resource_view_scan(data, pe), reason)


@pytest.mark.parametrize("kind", ["full_rva", "partial_rva", "file_alias"])
def test_resource_portable_section_mapping_must_be_unique_even_for_partial_rva_overlap(kind):
    content = resource_view_record(bytes(12)) + bytes(16)
    data, pe = resource_view_fixture(content=content, directory_size=32)
    if kind == "full_rva":
        other = NS(VirtualAddress=0x1000, SizeOfRawData=32, PointerToRawData=192)
    elif kind == "partial_rva":
        other = NS(VirtualAddress=0x1008, SizeOfRawData=4, PointerToRawData=192)
    else:
        other = NS(VirtualAddress=0x3000, SizeOfRawData=4, PointerToRawData=136)
    pe.sections.append(other)
    pe.FILE_HEADER.NumberOfSections = 2
    resource_assert_partial(resource_view_scan(data, pe), "directory_file_alias" if kind == "file_alias" else "directory_not_uniquely_file_backed")


def test_resource_portable_overlapping_body_and_header_and_zero_body_alias_are_rejected():
    content = (8).to_bytes(4, "little") + (0).to_bytes(4, "little") + bytes(4)
    data, pe = resource_view_fixture(records=[resource_view_row("a", 0), resource_view_row("b", 4)], content=content)
    resource_assert_partial(resource_view_scan(data, pe), "resource_range_overlap")
    data, pe = resource_view_fixture(records=[resource_view_row("a", 0), resource_view_row("b", 0)], content=resource_view_record(b""))
    resource_assert_partial(resource_view_scan(data, pe), "resource_range_alias")


def test_resource_portable_name_ambiguity_across_embedded_and_linked_discards_known_descriptor():
    linked = resource_view_table([NS()])
    data, pe = resource_view_fixture(records=[resource_view_row("same"), resource_view_row("same", implementation=NS(table=linked, row_index=1))],
                       extra_tables={"File": linked})
    result = resource_view_scan(data, pe)
    resource_assert_partial(result, "resource_name_ambiguity")
    assert result.coverage()["counts"]["descriptors_discarded"] == 2
    assert "all_descriptors_discarded_incomplete_inventory" in result.coverage()["reason_counts"]


def test_resource_portable_one_invalid_record_discards_otherwise_known_good_record():
    data, pe = resource_view_fixture(records=[resource_view_row("good"), resource_view_row("bad", 0xFFFFFFFF)])
    result = resource_view_scan(data, pe)
    resource_assert_partial(result, "resource_header_outside_directory")
    assert result.coverage()["counts"]["descriptors_discarded"] == 1


@pytest.mark.parametrize("limit,maximum", [
    ("max_resources", resources.MAX_RESOURCE_ROWS), ("max_resource_bytes", resources.MAX_RESOURCE_BYTES),
    ("max_total_bytes", resources.MAX_RESOURCE_BYTES), ("max_table_rows", resources.MAX_TABLE_ROWS),
    ("max_total_rows", resources.MAX_TOTAL_ROWS), ("max_sections", resources.MAX_SECTIONS),
])
@pytest.mark.parametrize("value", [0, -1, True, "1", "over_max"])
def test_resource_portable_all_limits_are_down_only_non_bool_positive_integers(limit, maximum, value):
    data, pe = resource_view_fixture()
    with pytest.raises(ValueError):
        resource_view_scan(data, pe, **{limit: maximum + 1 if value == "over_max" else value})


def test_resource_portable_single_and_total_byte_budget_boundaries():
    data, pe = resource_view_fixture(content=resource_view_record(b"abc"))
    assert resource_view_scan(data, pe, max_resource_bytes=3, max_total_bytes=3).coverage()["inventory_complete"]
    resource_assert_partial(resource_view_scan(data, pe, max_resource_bytes=2), "resource_byte_budget_exceeded")
    data, pe = resource_view_fixture(records=[resource_view_row("a", 0), resource_view_row("b", 5)], content=resource_view_record(b"a") + resource_view_record(b"b"))
    assert resource_view_scan(data, pe, max_total_bytes=2).coverage()["inventory_complete"]
    resource_assert_partial(resource_view_scan(data, pe, max_total_bytes=1), "resource_total_byte_budget_exceeded")


def test_resource_portable_resource_count_budget_boundary_and_no_partial_prefix_descriptors():
    data, pe = resource_view_fixture(records=[resource_view_row("a", 0), resource_view_row("b", 4)], content=resource_view_record(b"") + resource_view_record(b""))
    assert resource_view_scan(data, pe, max_resources=2).coverage()["inventory_complete"]
    result = resource_view_scan(data, pe, max_resources=1)
    resource_assert_partial(result, "resource_count_budget_exceeded")
    assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 0


def test_resource_portable_all_thirteen_tables_share_one_unique_row_budget_without_cross_product():
    extra = {name: resource_view_table([NS()] * 20_000) for name in resources.TABLE_NAMES[:4]}
    data, pe = resource_view_fixture(records=[], content=b"", extra_tables=extra)
    result = resource_view_scan(data, pe)
    assert result.coverage()["inventory_complete"]
    assert result.coverage()["work"]["unique_rows_reserved"] == 80_000
    assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 80_000
    pe.net.mdtables.ManifestResource = resource_view_table([resource_view_row()])
    result = resource_view_scan(data, pe)
    resource_assert_partial(result, "metadata_total_row_budget_exceeded")
    assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 0
    assert result.coverage()["work"]["reservation_demand_capped"] == 80_001


def test_resource_portable_metadata_table_budget_boundary():
    data, pe = resource_view_fixture(extra_tables={"TypeRef": resource_view_table([NS(), NS()])})
    assert resource_view_scan(data, pe, max_table_rows=2).coverage()["inventory_complete"]
    resource_assert_partial(resource_view_scan(data, pe, max_table_rows=1), "metadata_table_row_budget_exceeded")


def test_resource_portable_shared_snapshot_reuse_checks_source_and_reports_actual_identity_visits():
    data, pe = resource_view_fixture()
    first = resource_view_scan(data, pe)
    result = resource_view_scan(data, pe, row_snapshot=first._row_snapshot)
    assert result.coverage()["inventory_complete"]
    assert result.coverage()["work"]["shared_snapshot_reused"]
    assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 0
    assert result.coverage()["work"]["shared_snapshot_identity_visits"] == 1
    pe.net.mdtables.ManifestResource.rows[0] = resource_view_row("replacement")
    resource_assert_partial(resource_view_scan(data, pe, row_snapshot=first._row_snapshot), "shared_snapshot_source_changed")


def test_resource_portable_shared_snapshot_cannot_change_origin_or_raise_or_lower_limits_silently():
    data, pe = resource_view_fixture()
    first = resource_view_scan(data, pe)
    _, other_pe = resource_view_fixture()
    resource_assert_partial(resource_view_scan(data, other_pe, row_snapshot=first._row_snapshot), "shared_snapshot_origin_mismatch")
    resource_assert_partial(resource_view_scan(data, pe, row_snapshot=first._row_snapshot, max_total_rows=100), "shared_snapshot_limits_mismatch")
    resource_assert_partial(resource_view_scan(data, pe, row_snapshot=NS()), "shared_snapshot_origin_mismatch")


def test_resource_portable_private_name_body_offsets_tokens_and_unknown_state_do_not_leak():
    body = b"PRIVATE_BODY_SENTINEL"
    data, pe = resource_view_fixture(records=[resource_view_row("PRIVATE_NAME_SENTINEL")], content=resource_view_record(body),
                       extra_tables={"TypeRef": resource_view_table([NS(Name="PRIVATE_METADATA_SENTINEL", token="0xPRIVATE")])})
    result = resource_view_scan(data, pe)
    snapshot = result._row_snapshot
    public_before = json.dumps(result.coverage(), ensure_ascii=False, sort_keys=True)
    snapshot.states["ManifestResource"]["secret"] = "PRIVATE_EXTRA_SENTINEL"
    snapshot.states["ManifestResource"]["declared"] = 100
    assert json.dumps(result.coverage(), ensure_ascii=False, sort_keys=True) == public_before
    projections = [result.coverage(), result.__getstate__(), snapshot.__getstate__(), result._descriptors[0].__getstate__()]
    rendered = json.dumps(projections) + repr(result) + repr(snapshot) + repr(result._descriptors[0])
    assert "PRIVATE_" not in rendered
    assert "body_offset" not in rendered and "row_index" not in rendered and "0xPRIVATE" not in rendered
    snapshot.reasons["PRIVATE_REASON_SENTINEL"] = 1
    rejected = resource_view_scan(data, pe, row_snapshot=snapshot)
    resource_assert_partial(rejected, "shared_snapshot_source_changed")
    assert "PRIVATE_" not in json.dumps(rejected.coverage())


def test_resource_portable_missing_resource_members_are_fixed_reason_only():
    data, pe = resource_view_fixture(records=[NS(Name="PRIVATE_ROW", Offset=0)])
    resource_assert_partial(resource_view_scan(data, pe), "resource_row_access_failed")
    assert "PRIVATE_ROW" not in json.dumps(resource_view_scan(data, pe).coverage())


def test_resource_portable_input_must_be_immutable_exact_bytes_and_pe_can_be_absent():
    _, pe = resource_view_fixture()
    resource_assert_partial(resource_view_scan("not_bytes", pe), "input_type_invalid")
    resource_assert_partial(resource_view_scan(b"", NS()), "not_managed_pe")


def test_resource_portable_get_offset_first_match_is_not_used():
    data, pe = resource_view_fixture()
    pe.get_offset_from_rva = None
    assert resource_view_scan(data, pe).coverage()["inventory_complete"]


def test_resource_portable_default_resource_row_hard_boundary():
    limit = resources.MAX_RESOURCE_ROWS
    content = resource_view_record(b"") * limit
    data, pe = resource_view_fixture(records=[resource_view_row(f"r{index}", index * 4) for index in range(limit)], content=content)
    result = resource_view_scan(data, pe)
    assert result.coverage()["inventory_complete"]
    assert len(result._descriptors) == limit
    pe.net.mdtables.ManifestResource.rows.append(resource_view_row("over_limit", limit * 4))
    pe.net.mdtables.ManifestResource.num_rows += 1
    result = resource_view_scan(data, pe)
    resource_assert_partial(result, "resource_count_budget_exceeded")
    assert result.coverage()["counts"]["rows_skipped"] == limit + 1


def test_resource_portable_default_section_hard_boundary():
    data, pe = resource_view_fixture()
    pe.sections.extend(NS(VirtualAddress=0x3000 + index * 0x1000, SizeOfRawData=0, PointerToRawData=len(data))
                       for index in range(resources.MAX_SECTIONS - 1))
    pe.FILE_HEADER.NumberOfSections = resources.MAX_SECTIONS
    assert resource_view_scan(data, pe).coverage()["inventory_complete"]
    pe.sections.append(NS(VirtualAddress=0x80000, SizeOfRawData=0, PointerToRawData=len(data)))
    pe.FILE_HEADER.NumberOfSections += 1
    resource_assert_partial(resource_view_scan(data, pe), "section_count_invalid")


def test_resource_portable_uint32_exclusive_end_boundary_is_valid_without_wrap():
    data, pe = resource_view_fixture(content=resource_view_record(b""), directory_rva=(1 << 32) - 4)
    pe.sections[0].VirtualAddress = (1 << 32) - 4
    assert resource_view_scan(data, pe).coverage()["inventory_complete"]


def test_resource_portable_input_byte_budget_before_metadata_snapshot(monkeypatch):
    data, pe = resource_view_fixture()
    monkeypatch.setattr(resources, "MAX_INPUT_BYTES", 1)
    result = resource_view_scan(data, pe)
    resource_assert_partial(result, "input_byte_budget_exceeded")
    assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 0


@pytest.mark.parametrize("mutate", ["resource_count", "total_count", "tuple_type", "counter", "source_container"])
def test_resource_portable_shared_snapshot_rechecks_budgets_before_any_row_identity_visit(mutate):
    data, pe = resource_view_fixture()
    first = resource_view_scan(data, pe, max_resources=2, max_total_rows=4)
    snapshot = first._row_snapshot
    if mutate == "resource_count":
        rows = [resource_view_row(f"r{i}") for i in range(3)]
        pe.net.mdtables.ManifestResource.rows[:] = rows
        pe.net.mdtables.ManifestResource.num_rows = 3
        snapshot.rows["ManifestResource"] = tuple(rows)
    elif mutate == "total_count":
        rows = [NS() for _ in range(5)]
        pe.net.mdtables.TypeRef.rows[:] = rows
        pe.net.mdtables.TypeRef.num_rows = 5
        snapshot.rows["TypeRef"] = tuple(rows)
    elif mutate == "tuple_type":
        snapshot.rows["ManifestResource"] = list(snapshot.rows["ManifestResource"])
    elif mutate == "counter":
        snapshot.reserved = "PRIVATE_COUNTER_SENTINEL"
    else:
        snapshot.sources["ManifestResource"] = iter(snapshot.rows["ManifestResource"])
    result = resource_view_scan(data, pe, max_resources=2, max_total_rows=4, row_snapshot=snapshot)
    resource_assert_partial(result, "shared_snapshot_source_changed")
    assert result.coverage()["work"]["shared_snapshot_identity_visits"] == 0
    assert "PRIVATE_COUNTER" not in json.dumps(result.coverage()) + json.dumps(snapshot.__getstate__()) + repr(snapshot)


def test_resource_portable_source_shared_snapshot_does_not_claim_existing_resolver_cpu_visits_are_removed():
    data, pe = resource_view_fixture(extra_tables={"AssemblyRef": resource_view_table([NS(), NS()])})
    first = resource_view_scan(data, pe)
    second = resource_view_scan(data, pe, row_snapshot=first._row_snapshot)
    assert first.coverage()["work"]["unique_rows_reserved"] == 3
    assert second.coverage()["work"]["unique_rows_reserved"] == 3
    assert first.coverage()["work"]["snapshot_row_visits_this_call"] == 3
    assert second.coverage()["work"]["snapshot_row_visits_this_call"] == 0
    assert second.coverage()["work"]["shared_snapshot_identity_visits"] == 3
    assert "existing_resolver_cpu_visits" not in second.coverage()["work"]


@pytest.mark.parametrize("field", ["rows", "states", "reasons", "tables", "sources"])
def test_resource_portable_malformed_snapshot_maps_fail_closed_without_attributeerror(field):
    data, pe = resource_view_fixture()
    snapshot = resource_view_scan(data, pe)._row_snapshot
    setattr(snapshot, field, NS(private_marker="PRIVATE_SHAPE_SENTINEL"))
    result = resource_view_scan(data, pe, row_snapshot=snapshot)
    resource_assert_partial(result, "shared_snapshot_source_changed")
    assert result.coverage()["work"]["shared_snapshot_identity_visits"] == 0
    assert result.coverage()["work"]["shared_snapshot_reused"] is False
    assert result.coverage()["tables"]["ManifestResource"]["declared_status"] == "unavailable"
    assert "PRIVATE_" not in json.dumps(result.coverage())


def test_resource_portable_current_source_container_replacement_rejected_before_indexing():
    data, pe = resource_view_fixture()
    snapshot = resource_view_scan(data, pe)._row_snapshot
    pe.net.mdtables.ManifestResource.rows = iter([resource_view_row()])
    result = resource_view_scan(data, pe, row_snapshot=snapshot)
    resource_assert_partial(result, "shared_snapshot_source_changed")
    assert result.coverage()["work"]["shared_snapshot_identity_visits"] == 0


def test_resource_portable_extra_snapshot_keys_are_rejected_without_dynamic_iteration():
    data, pe = resource_view_fixture()
    snapshot = resource_view_scan(data, pe)._row_snapshot
    snapshot.rows["UNKNOWN_PRIVATE_TABLE"] = ()
    result = resource_view_scan(data, pe, row_snapshot=snapshot)
    resource_assert_partial(result, "shared_snapshot_source_changed")
    assert "UNKNOWN_PRIVATE" not in json.dumps(result.coverage())
