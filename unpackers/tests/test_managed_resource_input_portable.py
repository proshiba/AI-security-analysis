"""入力宣言束縛の独立陰性をrevision2へ移植する。既存fixtureは変更しない。

全人工2KiB CLR PEのimmutable bytesのみを静的dnfile parserへ渡す。
検体、OS binary、private case、network、compiler、CIL/CLR/VM実行は使わない。
true eagerは互換拡張せず明示partial拒否、未知callbackも実行しないことを期待する。
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import struct
from types import SimpleNamespace as NS

import pytest

from unpackers.tests.test_managed_resource_consumers_portable import ROOT as RESOURCE_ROOT, RESOURCE_NAMESPACE
import importlib
managed_resources = importlib.import_module(RESOURCE_NAMESPACE + ".managed_resources")
adapter = importlib.import_module(RESOURCE_NAMESPACE + ".dnfile_resource_adapter")
from unpackers.tests.test_managed_resource_synthetic_portable import (
    resource_build_synthetic_resource_pe, CLR_FILE_OFFSET, RESOURCE_FILE_OFFSET,
    _resource_assert_public_projection_is_private,
)

dnfile = pytest.importorskip("dnfile")


@pytest.fixture(scope="module", autouse=True)
def resource_module_origin():
    assert Path(managed_resources.__file__).resolve() == (RESOURCE_ROOT / "unpackers" / "managed_resources.py").resolve()
    assert Path(adapter.__file__).resolve() == (RESOURCE_ROOT / "unpackers" / "dnfile_resource_adapter.py").resolve()
    assert dnfile.__version__ == "0.18.0"


@pytest.fixture
def resource_parser(monkeypatch):
    opened = []
    resource_hooks = []

    def suppress_eager_resource_parser(_net, _pe):
        # true eager constructorの本文解釈だけを抑止する。helperからの追加呼出しは禁止。
        resource_hooks.append("constructor_resource_parse_suppressed")

    monkeypatch.setattr(dnfile.ClrData, "_init_resources", suppress_eager_resource_parser)

    def create(scope=None, *, lazy=True, fixture_override=None):
        resource_view_fixture = resource_build_synthetic_resource_pe(scope=scope) if fixture_override is None else fixture_override
        pe = dnfile.dnPE(data=resource_view_fixture.data, clr_lazy_load=lazy)
        assert pe.net is not None and pe.net.mdtables is not None
        opened.append(pe)
        return resource_view_fixture, pe

    yield create, resource_hooks
    for pe in opened:
        pe.close()


def resource_assert_complete(resource_view_scan, resource_view_fixture):
    _resource_assert_public_projection_is_private(resource_view_scan, resource_view_fixture)
    assert resource_view_scan.coverage()["status"] == "complete", resource_view_scan.coverage()["reason_counts"]
    assert resource_view_scan._descriptors and resource_view_scan._descriptors[0].name == resource_view_fixture.name


def resource_assert_partial(resource_view_scan, resource_view_fixture):
    _resource_assert_public_projection_is_private(resource_view_scan, resource_view_fixture)
    coverage = resource_view_scan.coverage()
    assert coverage["status"] == "partial"
    assert coverage["inventory_complete"] is False
    assert resource_view_scan._descriptors == ()
    assert coverage["counts"]["descriptors_retained"] == 0
    assert set(coverage["reason_counts"]) <= managed_resources.REASONS


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_portable_unmodified_lazy_artificial_controls_remain_complete(resource_parser, scope):
    create, hooks = resource_parser
    resource_view_fixture, pe = create(scope)
    before = len(hooks)
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(resource_view_scan, resource_view_fixture)
    assert len(hooks) == before
    assert pe.net.mdtables._loaded is False


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_portable_true_eager_is_explicitly_partial_not_provenance_equivalent(resource_parser, scope):
    create, hooks = resource_parser
    resource_view_fixture, pe = create(scope, lazy=False)
    assert type(pe.net.mdtables.ManifestResource.rows) is list
    assert "_loaded" not in vars(pe.net.mdtables)
    before = len(hooks)
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_partial(resource_view_scan, resource_view_fixture)
    assert len(hooks) == before


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("field", ["ResourcesRva", "ResourcesSize"])
def test_resource_portable_cli_resource_struct_view_must_match_input(resource_parser, reuse, field):
    create, hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    setattr(pe.net.struct, field, getattr(pe.net.struct, field) + (0x100 if field == "ResourcesRva" else 4))
    before = len(hooks)
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot if reuse else None)
    resource_assert_partial(resource_view_scan, resource_view_fixture)
    assert len(hooks) == before and pe.net.mdtables._loaded is False


def test_resource_portable_same_length_input_cli_cannot_use_an_older_parser_view(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    field_offset = CLR_FILE_OFFSET + 24
    current_rva = int.from_bytes(resource_view_fixture.data[field_offset:field_offset + 4], "little")
    changed = resource_view_fixture.data[:field_offset] + (current_rva + 0x100).to_bytes(4, "little") + resource_view_fixture.data[field_offset + 4:]
    assert len(changed) == len(resource_view_fixture.data) and changed != resource_view_fixture.data
    resource_assert_partial(managed_resources.describe_clr_resources(changed, pe), resource_view_fixture)


@pytest.mark.parametrize("reuse", [False, True])
def test_resource_portable_section_raw_size_view_must_match_input(resource_parser, reuse):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    pe.sections[0].SizeOfRawData -= 0x10
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot if reuse else None)
    resource_assert_partial(resource_view_scan, resource_view_fixture)


@pytest.mark.parametrize("change", ["name", "row_replacement", "registry_replacement", "raw_and_struct"])
def test_resource_portable_true_eager_mutations_never_become_complete(resource_parser, change):
    create, hooks = resource_parser
    resource_view_fixture, pe = create(lazy=False)
    metadata, resource_view_table = pe.net.mdtables, pe.net.mdtables.ManifestResource
    assert type(resource_view_table.rows) is list
    if change == "name":
        resource_view_table.rows[0].Name = NS(value="SYNTHETIC_UNBOUND_NAME_ONLY")
    elif change == "row_replacement":
        resource_view_table.rows[0] = NS(Name="SYNTHETIC_UNBOUND_NAME_ONLY", Offset=0, Implementation=None)
    elif change == "registry_replacement":
        metadata.tables[40] = NS(number=40)
    else:
        row = resource_view_table.rows[0]
        raw = row._data[:8] + (2).to_bytes(2, "little") + row._data[10:]
        row._data = raw
        row.struct.Name_StringIndex = 2
        resource_view_table._table_data = raw
    before = len(hooks)
    resource_assert_partial(managed_resources.describe_clr_resources(resource_view_fixture.data, pe), resource_view_fixture)
    assert len(hooks) == before


def test_resource_portable_true_eager_consistent_row_count_lowering_remains_partial(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create("File", lazy=False)
    resource_view_table = pe.net.mdtables.ManifestResource
    resource_view_table.num_rows = 0
    resource_view_table.rows = []
    resource_view_table._table_data = b""
    resource_view_table._tables_rowcounts[40] = 0
    resource_assert_partial(managed_resources.describe_clr_resources(resource_view_fixture.data, pe), resource_view_fixture)


def test_resource_portable_shared_heap_row_counts_cannot_override_input_counts(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    binding = first._row_snapshot.heap_binding
    row_counts = list(binding.row_counts)
    assert row_counts[0] == 0
    row_counts[0] = 1
    binding.row_counts = tuple(row_counts)
    pe.net.mdtables.ManifestResource._tables_rowcounts[0] = 1
    resource_assert_partial(managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot), resource_view_fixture)


def test_resource_portable_source_section_alias_cannot_be_removed_from_parser_view(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture = resource_build_synthetic_resource_pe()
    alias_header = struct.pack("<8sIIIIIIHHI", b".alias", 0x600, 0x6000,
                               0x600, 0x200, 0, 0, 0, 0, 0x40000040)
    data = resource_view_fixture.data[:0x86] + (2).to_bytes(2, "little") + resource_view_fixture.data[0x88:]
    data = data[:0x1A0] + alias_header + data[0x1A0 + len(alias_header):]
    alias_fixture, pe = create(fixture_override=replace(resource_view_fixture, data=data))
    assert len(pe.sections) == 2
    resource_assert_partial(managed_resources.describe_clr_resources(data, pe), alias_fixture)
    pe.sections = [pe.sections[0]]
    pe.FILE_HEADER.NumberOfSections = 1
    resource_assert_partial(managed_resources.describe_clr_resources(data, pe), alias_fixture)


def test_resource_portable_lazy_table_raw_bytes_cannot_be_relocated_outside_metadata_stream(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    resource_view_table = pe.net.mdtables.ManifestResource
    raw = resource_view_table._table_data
    replacement = raw[:8] + (2).to_bytes(2, "little") + raw[10:]
    changed = resource_view_fixture.data[:0x700] + replacement + resource_view_fixture.data[0x700 + len(replacement):]
    resource_view_table.file_offset = 0x700
    resource_view_table._table_data = replacement
    list.__setitem__(resource_view_table.rows, 0, None)
    resource_assert_partial(managed_resources.describe_clr_resources(changed, pe), resource_view_fixture)


def test_resource_portable_lazy_table_cannot_move_into_padding_inside_the_same_metadata_stream(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, original_pe = create()
    metadata, heap = original_pe.net.mdtables, original_pe.net.strings
    root_offset = object.__getattribute__(original_pe.net.metadata.struct, "__file_offset__")
    metadata_size = original_pe.net.struct.MetaDataSize
    stream_end = metadata.file_offset + metadata.struct.Size
    table_entry = object.__getattribute__(metadata.struct, "__file_offset__")
    heap_entry = object.__getattribute__(heap.struct, "__file_offset__")
    assert stream_end == heap.file_offset
    # 既存人工#~の末尾へ12byteのpaddingを挿入し、#Stringsを同じ12byteだけ後へ置く。
    metadata_bytes = resource_view_fixture.data[root_offset:stream_end] + bytes(12) + resource_view_fixture.data[stream_end:root_offset + metadata_size]
    data = resource_view_fixture.data[:root_offset] + metadata_bytes + resource_view_fixture.data[root_offset + metadata_size + 12:]
    for offset, value in (
        (CLR_FILE_OFFSET + 12, metadata_size + 12),
        (table_entry + 4, metadata.struct.Size + 12),
        (heap_entry, heap.struct.Offset + 12),
    ):
        data = data[:offset] + value.to_bytes(4, "little") + data[offset + 4:]
    padded_fixture, pe = create(fixture_override=replace(resource_view_fixture, data=data))
    baseline = managed_resources.describe_clr_resources(data, pe)
    if baseline.coverage()["status"] == "partial":
        # padding形状そのものが未対応なら、宣言不明なrowを採用しない境界は成立する。
        resource_assert_partial(baseline, padded_fixture)
        return
    resource_assert_complete(baseline, padded_fixture)
    resource_view_table = pe.net.mdtables.ManifestResource
    padding_offset = resource_view_table.file_offset + len(resource_view_table._table_data)
    replacement = resource_view_table._table_data[:8] + (2).to_bytes(2, "little") + resource_view_table._table_data[10:]
    assert padding_offset + len(replacement) <= pe.net.mdtables.file_offset + pe.net.mdtables.struct.Size
    changed = data[:padding_offset] + replacement + data[padding_offset + len(replacement):]
    resource_view_table.file_offset = padding_offset
    resource_view_table._table_data = replacement
    list.__setitem__(resource_view_table.rows, 0, None)
    resource_assert_partial(managed_resources.describe_clr_resources(changed, pe), padded_fixture)


def test_resource_portable_table_stream_name_bytes_must_match_metadata_registry(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    header = pe.net.mdtables.struct
    entry_offset = object.__getattribute__(header, "__file_offset__")
    assert resource_view_fixture.data[entry_offset + 8:entry_offset + 11] == b"#~\x00"
    changed = resource_view_fixture.data[:entry_offset + 8] + b"#X\x00" + resource_view_fixture.data[entry_offset + 11:]
    resource_assert_partial(managed_resources.describe_clr_resources(changed, pe), resource_view_fixture)


def test_resource_portable_table_stream_must_be_a_declared_root_entry_not_an_input_lookalike(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, original_pe = create()
    root_offset = object.__getattribute__(original_pe.net.metadata.struct, "__file_offset__")
    original_metadata = original_pe.net.mdtables
    original_stream = resource_view_fixture.data[original_metadata.file_offset:original_metadata.file_offset + original_metadata.struct.Size]
    original_row = original_metadata.ManifestResource._table_data
    alternate_row = original_row[:8] + (2).to_bytes(2, "little") + original_row[10:]
    alternate_stream = original_stream[:-len(original_row)] + alternate_row
    fake_entry = root_offset + 0x1C0
    fake_relative = 0x1E0
    fake_stream = root_offset + fake_relative
    # rootが宣言するstream数と2つのentryは変えず、directory内paddingへlookalikeを置く。
    data = resource_view_fixture.data[:CLR_FILE_OFFSET + 12] + (0x240).to_bytes(4, "little") + resource_view_fixture.data[CLR_FILE_OFFSET + 16:]
    fake_header = struct.pack("<II4s", fake_relative, len(alternate_stream), b"#~\x00\x00")
    data = data[:fake_entry] + fake_header + data[fake_entry + len(fake_header):]
    data = data[:fake_stream] + alternate_stream + data[fake_stream + len(alternate_stream):]
    alternate_fixture, pe = create(fixture_override=replace(resource_view_fixture, data=data))
    resource_assert_complete(managed_resources.describe_clr_resources(data, pe), alternate_fixture)
    metadata, resource_view_table = pe.net.mdtables, pe.net.mdtables.ManifestResource
    object.__setattr__(metadata.struct, "__file_offset__", fake_entry)
    metadata.struct.Offset = fake_relative
    metadata.struct.Size = len(alternate_stream)
    metadata.file_offset = fake_stream
    metadata.rva = pe.net.struct.MetaDataRva + fake_relative
    resource_view_table.file_offset = fake_stream + len(alternate_stream) - len(alternate_row)
    resource_view_table.rva = pe.net.struct.MetaDataRva + resource_view_table.file_offset - root_offset
    resource_view_table._table_data = alternate_row
    list.__setitem__(resource_view_table.rows, 0, None)
    resource_view_scan = managed_resources.describe_clr_resources(data, pe)
    if resource_view_scan._descriptors:
        assert resource_view_scan._descriptors[0].name != alternate_fixture.name
    resource_assert_partial(resource_view_scan, alternate_fixture)


def test_resource_portable_empty_table_layout_extra_data_requires_four_input_bytes():
    # maskが空でもExtraData宣言の4byteをstream外へ飛ばして成功にしない。
    header = struct.pack("<IBBBBQQ", 0, 2, 0, 0x40, 1, 0, 0)
    assert len(header) == 24
    assert adapter.clr_input_binding.canonical_table_layout(header, 0, len(header)) is None


@pytest.mark.parametrize("where", ["limits", "declared_status"])
def test_resource_portable_malformed_shared_scalars_do_not_invoke_unknown_equality(resource_parser, where):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    calls = []

    class EqualityMarker:
        def __eq__(self, _other):
            calls.append("synthetic_scalar_equality_called")
            return False

    snapshot = first._row_snapshot
    if where == "limits":
        snapshot.limits = EqualityMarker()
    else:
        snapshot.states["ManifestResource"]["declared_status"] = EqualityMarker()
    resource_assert_partial(managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=snapshot), resource_view_fixture)
    assert calls == []


def test_resource_portable_shared_same_count_cached_row_replacement_is_partial(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    resource_view_table = pe.net.mdtables.ManifestResource
    list.__setitem__(resource_view_table.rows, 0, None)
    resource_assert_partial(managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot), resource_view_fixture)


def test_resource_portable_existing_strings_heap_raw_guard_remains_partial(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    pe.net.strings.__data__ = b"X" + pe.net.strings.__data__[1:]
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot)
    resource_assert_partial(resource_view_scan, resource_view_fixture)
    assert "dnfile_string_heap_provenance_invalid" in resource_view_scan.coverage()["reason_counts"]
