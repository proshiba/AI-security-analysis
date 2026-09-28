"""全人工CLR PEと通常codeのloader fault injectionで専用adapterの陰性境界を試験する。"""

from __future__ import annotations

from types import MethodType, SimpleNamespace as NS
from dataclasses import replace
import importlib
import json

import pytest

from unpackers.tests.test_managed_resource_synthetic_portable import resource_build_synthetic_resource_pe
from unpackers.tests.test_managed_resource_consumers_portable import ROOT as RESOURCE_ROOT, RESOURCE_NAMESPACE
import importlib
managed_resources = importlib.import_module(RESOURCE_NAMESPACE + ".managed_resources")
adapter = importlib.import_module(RESOURCE_NAMESPACE + ".dnfile_resource_adapter")

dnfile = pytest.importorskip("dnfile")
from dnfile import base, mdtable, utils


def resource_parse_synthetic(scope=None):
    resource_view_fixture = resource_build_synthetic_resource_pe(scope=scope)
    pe = dnfile.dnPE(data=resource_view_fixture.data, clr_lazy_load=True)
    return resource_view_fixture, pe


def resource_adapter_partial(resource_view_fixture, pe, reason=None, **limits):
    result = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, **limits)
    coverage = result.coverage()
    assert coverage["status"] == "partial"
    assert result._descriptors == ()
    assert coverage["counts"]["descriptors_retained"] == 0
    assert set(coverage["reason_counts"]) <= managed_resources.REASONS
    assert pe.net.mdtables._loaded is False
    if reason:
        assert reason in coverage["reason_counts"]
    return result


@pytest.mark.parametrize("kind", ["function", "method", "foreign_owner", "instance_parser_override"])
def test_resource_portable_callback_names_are_not_enough_and_unknown_callbacks_never_run(kind):
    resource_view_fixture, pe = resource_parse_synthetic()
    other_fixture, other_pe = resource_parse_synthetic()
    calls = []

    def _lazy_parse_rows(*_args):
        calls.append("unknown_callback_called")
        raise AssertionError("未知callbackは実行してはいけません")

    resource_view_table = pe.net.mdtables.ManifestResource
    try:
        if kind == "function":
            resource_view_table.rows.eval_func = _lazy_parse_rows
        elif kind == "method":
            resource_view_table.rows.eval_func = MethodType(_lazy_parse_rows, resource_view_table)
        elif kind == "foreign_owner":
            resource_view_table.rows.eval_func = other_pe.net.mdtables.ManifestResource._lazy_parse_rows
        else:
            resource_view_table._lazy_parse_row = MethodType(_lazy_parse_rows, resource_view_table)
        result = resource_adapter_partial(resource_view_fixture, pe, "dnfile_lazy_callback_unreviewed")
        assert calls == []
        assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 0
    finally:
        pe.close()
        other_pe.close()


def test_resource_portable_lazy_subclass_and_generator_are_not_generalized():
    resource_view_fixture, pe = resource_parse_synthetic()
    resource_view_table = pe.net.mdtables.ManifestResource

    class UnknownLazyList(utils.LazyList):
        pass

    try:
        resource_view_table.rows = UnknownLazyList(resource_view_table._lazy_parse_rows, 1)
        resource_adapter_partial(resource_view_fixture, pe, "metadata_rows_container_unsupported")
        resource_view_table.rows = iter([NS()])
        resource_adapter_partial(resource_view_fixture, pe, "metadata_rows_container_unsupported")
    finally:
        pe.close()


@pytest.mark.parametrize("kind", ["registry", "table_list", "row_class", "metadata_class", "table_number"])
def test_resource_portable_same_table_and_metadata_class_provenance(kind):
    resource_view_fixture, pe = resource_parse_synthetic()
    metadata, resource_view_table = pe.net.mdtables, pe.net.mdtables.ManifestResource
    try:
        if kind == "registry":
            metadata.tables[40] = NS()
        elif kind == "table_list":
            metadata.tables_list = [resource_view_table, resource_view_table]
        elif kind == "row_class":
            resource_view_table._row_class = NS
        elif kind == "metadata_class":
            pe.net.mdtables = NS(ManifestResource=resource_view_table, _loaded=False)
        else:
            resource_view_table.number = 39
        reason = ("dnfile_metadata_registry_incomplete" if kind == "table_list" else
                  "dnfile_string_heap_provenance_invalid" if kind == "metadata_class" else "dnfile_lazy_table_provenance_invalid")
        resource_adapter_partial(resource_view_fixture, pe, reason)
    finally:
        pe.close()


@pytest.mark.parametrize("kind", ["declared", "actual", "table_cap", "total_cap"])
def test_resource_portable_all_caps_precede_any_lazy_parser_callback(kind):
    resource_view_fixture, pe = resource_parse_synthetic(scope="File")
    resource_view_table = pe.net.mdtables.ManifestResource
    limits = {}
    try:
        if kind == "declared":
            resource_view_table.num_rows = 2
        elif kind == "actual":
            list.append(resource_view_table.rows, None)
        elif kind == "table_cap":
            pe.net.mdtables.File.num_rows = 2
            list.append(pe.net.mdtables.File.rows, None)
            limits["max_table_rows"] = 1
        else:
            limits["max_total_rows"] = 1
        result = resource_adapter_partial(resource_view_fixture, pe, **limits)
        assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 0
        assert result.coverage()["work"]["dnfile_lazy_snapshot_row_visits_this_call"] == 0
    finally:
        pe.close()


@pytest.mark.parametrize("kind", ["data_truncated", "data_identity", "offset", "row_size", "loaded_state", "cached_row"])
def test_resource_portable_truncated_or_changed_lazy_table_cannot_become_complete(kind):
    resource_view_fixture, pe = resource_parse_synthetic()
    resource_view_table = pe.net.mdtables.ManifestResource
    try:
        if kind == "data_truncated":
            resource_view_table._table_data = resource_view_table._table_data[:-1]
        elif kind == "data_identity":
            resource_view_table._table_data = bytes(len(resource_view_table._table_data))
        elif kind == "offset":
            resource_view_table.file_offset = -1
        elif kind == "row_size":
            resource_view_table.row_size = 129
        elif kind == "loaded_state":
            resource_view_table._loaded = base.LoadState.Unloaded
        else:
            list.__setitem__(resource_view_table.rows, 0, NS(_loaded=base.LoadState.LazyLoaded))
        resource_adapter_partial(resource_view_fixture, pe)
    finally:
        pe.close()


def test_resource_portable_fault_injected_lazy_parse_failure_preserves_partial(monkeypatch):
    resource_view_fixture, pe = resource_parse_synthetic()
    original = adapter.materialize_lazy_row

    def failure(data, metadata, name, resource_view_table, source, index, expected_count):
        if name == "ManifestResource":
            return None, "dnfile_lazy_materialization_failed"
        return original(data, metadata, name, resource_view_table, source, index, expected_count)

    monkeypatch.setattr(adapter, "materialize_lazy_row", failure)
    try:
        result = resource_adapter_partial(resource_view_fixture, pe, "dnfile_lazy_materialization_failed")
        assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 1
    finally:
        pe.close()


def test_resource_portable_source_length_change_between_preflight_and_materialization_is_partial(monkeypatch):
    resource_view_fixture, pe = resource_parse_synthetic()
    original = adapter.materialize_lazy_row

    def truncate(data, metadata, name, resource_view_table, source, index, expected_count):
        if name == "ManifestResource":
            source.truncate(0)
        return original(data, metadata, name, resource_view_table, source, index, expected_count)

    monkeypatch.setattr(adapter, "materialize_lazy_row", truncate)
    try:
        resource_adapter_partial(resource_view_fixture, pe, "dnfile_lazy_source_changed")
    finally:
        pe.close()


def test_resource_portable_lazy_snapshot_reuse_is_bounded_and_does_not_full_load():
    resource_view_fixture, pe = resource_parse_synthetic(scope="AssemblyRef")
    try:
        first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        second = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot)
        assert first.coverage()["status"] == second.coverage()["status"] == "complete"
        assert second.coverage()["work"]["shared_snapshot_identity_visits"] == 2
        assert second.coverage()["work"]["shared_snapshot_reused"] is True
        assert first.coverage()["work"]["dnfile_lazy_snapshot_row_visits_this_call"] == 2
        assert second.coverage()["work"]["dnfile_lazy_snapshot_row_visits_this_call"] == 0
        assert second.coverage()["work"]["dnfile_lazy_identity_visits_this_call"] == 2
        assert pe.net.mdtables._loaded is False
        resource_view_table = pe.net.mdtables.ManifestResource
        resource_view_table.rows.eval_func = lambda *_args: None
        resource_adapter_partial(resource_view_fixture, pe, "dnfile_lazy_callback_unreviewed", row_snapshot=first._row_snapshot)
    finally:
        pe.close()


@pytest.mark.parametrize("kind", ["foreign_row", "same_table_row", "unknown_cached_row"])
def test_resource_portable_same_count_cached_row_replacement_is_partial_on_reuse(kind):
    resource_view_fixture, pe = resource_parse_synthetic()
    foreign_fixture, foreign_pe = resource_parse_synthetic()
    calls = []

    class UnknownRow:
        def __bool__(self):
            calls.append("unknown_bool_called")
            return True

        def __eq__(self, _other):
            calls.append("unknown_eq_called")
            return False

    try:
        first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        resource_view_table = pe.net.mdtables.ManifestResource
        replacement = (foreign_pe.net.mdtables.ManifestResource.rows[0] if kind == "foreign_row" else
                       resource_view_table._lazy_parse_row(None, 0) if kind == "same_table_row" else UnknownRow())
        list.__setitem__(resource_view_table.rows, 0, replacement)
        reason = "shared_snapshot_source_changed" if kind == "same_table_row" else "dnfile_lazy_row_invalid"
        second = resource_adapter_partial(resource_view_fixture, pe, reason, row_snapshot=first._row_snapshot)
        assert second.coverage()["work"]["shared_snapshot_identity_visits"] == 1
        assert calls == []
    finally:
        pe.close()
        foreign_pe.close()


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_portable_already_loaded_real_parser_tables_are_accepted_without_loading_resources(scope):
    resource_view_fixture, pe = resource_parse_synthetic(scope=scope)
    try:
        metadata = pe.net.mdtables
        # 全人工・最大2tableのstatic parserだけを事前にLoadedへ進める。
        metadata.ManifestResource._full_loader()
        assert metadata._loaded is True
        assert all(resource_view_table._loaded is base.LoadState.Loaded for resource_view_table in metadata.tables_list)
        assert pe.net._resources is None
        first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        second = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot)
        assert first.coverage()["status"] == second.coverage()["status"] == "complete"
        assert first._descriptors[0].name == resource_view_fixture.name
        assert first.coverage()["work"]["dnfile_lazy_snapshot_row_visits_this_call"] == (1 if scope is None else 2)
        assert second.coverage()["work"]["shared_snapshot_identity_visits"] == (1 if scope is None else 2)
        assert pe.net._resources is None
    finally:
        pe.close()


def test_resource_portable_changed_row_truth_callback_is_rejected_before_it_runs(monkeypatch):
    resource_view_fixture, pe = resource_parse_synthetic()
    calls = []

    def unknown_bool(_self):
        calls.append("unknown_bool_called")
        return True

    try:
        row_class = type(pe.net.mdtables.ManifestResource.rows[0])
        monkeypatch.setattr(row_class, "__bool__", unknown_bool, raising=False)
        resource_adapter_partial(resource_view_fixture, pe, "dnfile_lazy_callback_unreviewed")
        assert calls == []
    finally:
        pe.close()


@pytest.mark.parametrize("kind", ["getitem", "version"])
def test_resource_portable_changed_parser_implementation_is_not_reviewed_automatically(kind, monkeypatch):
    resource_view_fixture, pe = resource_parse_synthetic()
    try:
        if kind == "getitem":
            monkeypatch.setattr(utils.LazyList, "__getitem__", lambda *_args: None)
            resource_adapter_partial(resource_view_fixture, pe, "dnfile_lazy_callback_unreviewed")
        else:
            monkeypatch.setattr(dnfile, "__version__", "0.19.0")
            resource_adapter_partial(resource_view_fixture, pe, "dnfile_lazy_dependency_unreviewed")
    finally:
        pe.close()


@pytest.mark.parametrize("kind", ["version", "version_with_ordinary_rows", "missing_loader_code", "missing_table_class"])
def test_resource_portable_unsupported_dependency_initialization_fails_closed_without_import_exception(kind, monkeypatch):
    resource_view_fixture, pe = resource_parse_synthetic()
    try:
        with monkeypatch.context() as patch:
            if kind in ("version", "version_with_ordinary_rows"):
                if kind == "version_with_ordinary_rows":
                    resource_view_table = pe.net.mdtables.ManifestResource
                    resource_view_table.rows = [resource_view_table.rows[0]]
                patch.setattr(dnfile, "__version__", "0.19.0")
            elif kind == "missing_loader_code":
                patch.setattr(adapter.stream.MetaDataTables, "parse", lambda *_args, **_kwargs: None)
            else:
                patch.delattr(mdtable, "TypeRef")
            importlib.reload(adapter)
            assert adapter.dependency_failure() == "dnfile_lazy_dependency_unreviewed"
            resource_adapter_partial(resource_view_fixture, pe, "dnfile_lazy_dependency_unreviewed")
    finally:
        importlib.reload(adapter)
        pe.close()


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("kind", ["raw", "offset", "size", "foreign_table_heap", "foreign_net_heap", "registry", "stream_list"])
def test_resource_portable_strings_heap_is_source_and_registry_bound(kind, reuse):
    resource_view_fixture, pe = resource_parse_synthetic(scope="File")
    foreign_fixture, foreign_pe = resource_parse_synthetic(scope="File")
    try:
        first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        heap = pe.net.strings
        if kind == "raw":
            heap.__data__ = b"X" + heap.__data__[1:]
        elif kind == "offset":
            heap.file_offset += 1
        elif kind == "size":
            heap.struct.Size += 1
        elif kind == "foreign_table_heap":
            pe.net.mdtables.ManifestResource._strings_heap = foreign_pe.net.strings
        elif kind == "foreign_net_heap":
            pe.net.strings = foreign_pe.net.strings
        elif kind == "registry":
            pe.net.metadata.streams[b"#Strings"] = foreign_pe.net.strings
        else:
            pe.net.metadata.streams_list = [pe.net.mdtables, foreign_pe.net.strings]
        result = resource_adapter_partial(resource_view_fixture, pe, row_snapshot=first._row_snapshot if reuse else None)
        assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 0
        assert result.coverage()["work"]["shared_snapshot_identity_visits"] == 0
    finally:
        pe.close()
        foreign_pe.close()


@pytest.mark.parametrize("reuse", [False, True])
@pytest.mark.parametrize("field,value", [("Offset", 1), ("Name_StringIndex", 2), ("Implementation_CodedIndex", 4)])
def test_resource_portable_same_row_struct_mutation_cannot_override_input_rowbytes(field, value, reuse):
    resource_view_fixture, pe = resource_parse_synthetic()
    try:
        first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        row = pe.net.mdtables.ManifestResource.rows[0]
        original_data = row._data
        setattr(row.struct, field, value)
        assert row._data is original_data
        resource_adapter_partial(resource_view_fixture, pe, "dnfile_resource_view_invalid", row_snapshot=first._row_snapshot if reuse else None)
    finally:
        pe.close()


def test_resource_portable_shared_heap_comparison_is_once_per_call_and_privately_projected():
    resource_view_fixture, pe = resource_parse_synthetic(scope="AssemblyRef")
    try:
        size = len(pe.net.strings.__data__)
        first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, max_string_heap_bytes=size)
        second = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, max_string_heap_bytes=size, row_snapshot=first._row_snapshot)
        assert first.coverage()["status"] == second.coverage()["status"] == "complete"
        assert first.coverage()["work"]["dnfile_string_heap_bytes_compared_this_call"] == size
        assert second.coverage()["work"]["dnfile_string_heap_bytes_compared_this_call"] == size
        assert first.coverage()["work"]["dnfile_lazy_table_count"] == 2
        public = json.dumps(first.coverage(), sort_keys=True) + repr(first._row_snapshot.heap_binding)
        public += json.dumps(first._row_snapshot.heap_binding.__getstate__())
        assert resource_view_fixture.name not in public
        result = resource_adapter_partial(resource_view_fixture, pe, "dnfile_string_heap_budget_exceeded", max_string_heap_bytes=size - 1)
        assert result.coverage()["work"]["dnfile_string_heap_bytes_compared_this_call"] == 0
        assert result.coverage()["work"]["snapshot_row_visits_this_call"] == 0
        resource_adapter_partial(resource_view_fixture, pe, "shared_snapshot_limits_mismatch", max_string_heap_bytes=size - 1, row_snapshot=first._row_snapshot)
    finally:
        pe.close()


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, "1", (16 << 20) + 1])
def test_resource_portable_shared_heap_budget_is_down_only_non_bool_positive(value):
    resource_view_fixture, pe = resource_parse_synthetic()
    try:
        with pytest.raises(ValueError):
            managed_resources.describe_clr_resources(resource_view_fixture.data, pe, max_string_heap_bytes=value)
    finally:
        pe.close()


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_portable_real_dnfile_zero_row_manifest_declared_in_mask_is_not_silently_absent(scope):
    resource_view_fixture, original_pe = resource_parse_synthetic(scope=scope)
    try:
        # 人工PE内の#~ row countだけを0にした人工入力。通常binaryは一切参照しない。
        count_offset = original_pe.net.mdtables.file_offset + 24 + (0 if scope is None else 4)
        data = resource_view_fixture.data[:count_offset] + bytes(4) + resource_view_fixture.data[count_offset + 4:]
        zero_fixture = replace(resource_view_fixture, data=data)
    finally:
        original_pe.close()
    pe = dnfile.dnPE(data=zero_fixture.data, clr_lazy_load=True)
    try:
        # dnfile 0.18.0はempty tableをfalseと判定しregistryへ登録せず、parse warningを残す。
        assert pe.net.mdtables.ManifestResource is None
        assert 40 not in pe.net.mdtables.tables
        resource_adapter_partial(zero_fixture, pe, "dnfile_metadata_registry_incomplete")
    finally:
        pe.close()


def test_resource_portable_declared_count_and_container_cannot_be_consistently_lowered_below_input():
    resource_view_fixture, pe = resource_parse_synthetic()
    try:
        resource_view_table = pe.net.mdtables.ManifestResource
        resource_view_table.num_rows = 0
        resource_view_table._tables_rowcounts[40] = 0
        resource_view_table.rows.truncate(0)
        resource_view_table._table_data = b""
        resource_adapter_partial(resource_view_fixture, pe, "dnfile_table_canonical_position_mismatch")
    finally:
        pe.close()
