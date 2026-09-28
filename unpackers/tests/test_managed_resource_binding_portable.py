"""raw PE/CLRと固定table layoutの境界を人工bytesだけで照合する。"""

from pathlib import Path
import struct

import pytest

from unpackers.tests.test_managed_resource_consumers_portable import ROOT as RESOURCE_ROOT, RESOURCE_NAMESPACE
import importlib
binding = importlib.import_module(RESOURCE_NAMESPACE + ".clr_input_binding")
from unpackers.tests.test_managed_resource_synthetic_portable import resource_build_synthetic_resource_pe, _resource_insert

dnfile = pytest.importorskip("dnfile")


@pytest.mark.parametrize("field,value", [
    (0x3C, 0), (0x3C, 0xFFFFFFF0), (0x86, 97), (0x94, 4097),
    (0x98, 0x107), (0xF4, 14), (0xF4, 17),
    (0x168, 0xFFFFFFFF), (0x16C, 71), (0x16C, 4097),
    (0x200, 71), (0x200, 73),
])
def test_resource_portable_raw_header_mutation_fails_even_with_old_parser_view(field, value):
    resource_view_fixture = resource_build_synthetic_resource_pe()
    pe = dnfile.dnPE(data=resource_view_fixture.data, clr_lazy_load=True)
    try:
        assert binding.verify_pe_clr_input(resource_view_fixture.data, pe)
        size = 2 if field in (0x86, 0x94, 0x98) else 4
        changed = _resource_insert(resource_view_fixture.data, field, value.to_bytes(size, "little"))
        assert binding.verify_pe_clr_input(changed, pe) is False
    finally:
        pe.close()


def _resource_tables(rows, *, flags=0, version=(2, 0), extra=b"", payload=b""):
    mask = sum(1 << number for number in rows)
    return (struct.pack("<IBBBBQQ", 0, *version, flags, 1, mask, 0)
            + b"".join(count.to_bytes(4, "little") for count in rows.values()) + extra + payload)


@pytest.mark.parametrize("header", [
    _resource_tables({45: 0}), _resource_tables({63: 0}), _resource_tables({}, version=(1, 0)),
    _resource_tables({}, flags=0x08), _resource_tables({}, flags=0x40),
    _resource_tables({40: 1}), _resource_tables({40: 0})[:-1],
])
def test_resource_portable_unknown_or_truncated_layout_is_not_validated_empty(header):
    assert binding.canonical_table_layout(header, 0, len(header)) is None


def test_resource_portable_zero_rows_and_extra_data_have_bounded_canonical_positions():
    raw = _resource_tables({40: 0}, flags=0x40, extra=bytes(4))
    counts, layout, heaps = binding.canonical_table_layout(raw, 0, len(raw))
    assert counts[40] == 0 and layout[40] == (32, 12, 0) and heaps == (2, 2, 2)


@pytest.mark.parametrize("count,expected", [(32767, 2), (32768, 4)])
def test_resource_portable_coded_index_width_boundary_uses_all_declared_target_counts(count, expected):
    counts = [0] * 64
    counts[10] = count
    # MethodSpecのMethodDefOrRefは1bit tagを持つ。
    assert binding._row_size(43, tuple(counts), (2, 2, 2)) == expected + 2


def test_resource_portable_custom_attribute_includes_method_spec_target_for_independent_layout():
    counts = [0] * 64
    counts[43] = 2048
    assert binding._row_size(12, tuple(counts), (2, 2, 2)) == 8


@pytest.mark.parametrize("heaps,expected", [((2, 2, 2), 12), ((4, 2, 2), 14)])
def test_resource_portable_manifest_resource_string_heap_width_is_fixed_schema(heaps, expected):
    assert binding._row_size(40, (0,) * 64, heaps) == expected


@pytest.mark.parametrize("sections", [((0x1000, 0x100, 0), (0x1000, 0x100, 0x100)),
                                     ((0x1000, 0x100, 0), (0x2000, 0x100, 0)),
                                     ((0x1000, 0x80, 0), (0x1040, 0x80, 0x100))])
def test_resource_portable_raw_mapping_rejects_rva_alias_file_alias_and_partial_overlap(sections):
    assert binding.unique_file_span(sections, 0x1040, 0x40) is None
