"""元MetadataResolverを変更しない固定module factoryを人工PEだけで試験する。"""

from pathlib import Path

import pytest

from unpackers.tests.test_managed_resource_consumers_portable import ROOT as RESOURCE_ROOT, RESOURCE_NAMESPACE
import importlib
factory = importlib.import_module(RESOURCE_NAMESPACE + ".managed_resource_snapshot")
resources = importlib.import_module(RESOURCE_NAMESPACE + ".managed_resources")
from unpackers.tests.test_managed_resource_views_portable import resource_view_fixture
from unpackers.tests.test_managed_resource_synthetic_portable import resource_build_synthetic_resource_pe

dnfile = pytest.importorskip("dnfile")


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_portable_fixed_factory_returns_exact_original_class_with_one_group_reservation(scope):
    artificial = resource_build_synthetic_resource_pe(scope=scope)
    pe = dnfile.dnPE(data=artificial.data, clr_lazy_load=True)
    try:
        resource_view_scan = resources.describe_clr_resources(artificial.data, pe)
        resolver, work = factory.resolver_from_resource_snapshot(pe, data=artificial.data, row_snapshot=resource_view_scan._row_snapshot)
        assert type(resolver) is factory.MetadataResolver
        assert resolver.coverage()["complete"] is True
        assert work["accepted"] is True and work["unique_rows_reserved_this_resolver"] == 0
        assert work["group_unique_rows_reserved"] == (1 if scope is None else 2)
        assert work["resolver_row_reference_visits"] == (scope == "AssemblyRef")
        assert pe.net.mdtables._loaded is False
    finally:
        pe.close()


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_portable_production_shape_prepare_and_consume_reuse_the_same_source(scope):
    artificial = resource_build_synthetic_resource_pe(scope=scope)
    pe = dnfile.dnPE(data=artificial.data, clr_lazy_load=True)
    try:
        resource_view_scan, resolver, work = factory.prepare_resource_snapshot(artificial.data, pe)
        fresh = factory.revalidated_resource_scan(artificial.data, resource_view_scan)
        assert fresh.coverage()["inventory_complete"] is True
        assert fresh.coverage()["work"]["snapshot_row_visits_this_call"] == 0
        assert fresh.coverage()["work"]["shared_snapshot_identity_visits"] == work["group_unique_rows_reserved"]
        assert resolver.coverage()["complete"] is True
        assert fresh._descriptors[0].name == artificial.name
    finally:
        pe.close()


@pytest.mark.parametrize("change", ["foreign", "descriptor", "cli", "unknown_budget_key", "fake_coverage"])
def test_resource_portable_production_shape_consumer_rejects_stale_or_forged_inputs(change):
    artificial = resource_build_synthetic_resource_pe()
    pe = dnfile.dnPE(data=artificial.data, clr_lazy_load=True)
    try:
        resource_view_scan, _, _ = factory.prepare_resource_snapshot(artificial.data, pe)
        if change == "foreign":
            with pytest.raises(ValueError, match="resource_consumer_origin_mismatch"):
                factory.revalidated_resource_scan(bytes(bytearray(artificial.data)), resource_view_scan)
        elif change == "descriptor":
            resource_view_scan._descriptors[0].body_offset += 1
            assert factory.revalidated_resource_scan(artificial.data, resource_view_scan)._descriptors == ()
        elif change == "cli":
            pe.net.struct.ResourcesSize += 1
            assert factory.revalidated_resource_scan(artificial.data, resource_view_scan).coverage()["inventory_complete"] is False
        elif change == "fake_coverage":
            resource_view_scan._coverage = {"inventory_complete": True}
            with pytest.raises(ValueError, match="resource_consumer_origin_mismatch"):
                factory.revalidated_resource_scan(artificial.data, resource_view_scan)
        else:
            calls = []

            class Marker:
                def __hash__(self):
                    return hash("max_resources")

                def __eq__(self, _other):
                    calls.append("synthetic_unknown_equality_called")
                    return False

            value = resource_view_scan._coverage["budgets"].pop("max_resources")
            resource_view_scan._coverage["budgets"][Marker()] = value
            calls.clear()
            with pytest.raises(ValueError, match="resource_consumer_budget_invalid"):
                factory.revalidated_resource_scan(artificial.data, resource_view_scan)
            assert calls == []
    finally:
        pe.close()


def test_resource_portable_production_shape_parser_view_never_produces_descriptors():
    data, pe = resource_view_fixture()
    resource_view_scan, resolver, work = factory.prepare_resource_snapshot(data, pe)
    assert resource_view_scan._descriptors == () and resource_view_scan.coverage()["inventory_complete"] is False
    assert resolver.coverage()["complete"] is False and work["accepted"] is False
    fresh = factory.revalidated_resource_scan(data, resource_view_scan)
    assert fresh._descriptors == () and fresh.coverage()["parser_view_only"] is True


@pytest.mark.parametrize("change", ["foreign_bytes", "changed_bytes", "row_identity", "limits", "heap_bytes", "cli"])
def test_resource_portable_factory_invalid_origin_stays_unresolved_and_does_not_reserve_again(change):
    artificial = resource_build_synthetic_resource_pe()
    pe = dnfile.dnPE(data=artificial.data, clr_lazy_load=True)
    try:
        resource_view_scan = resources.describe_clr_resources(artificial.data, pe)
        data, maximum = artificial.data, 20_000
        if change == "foreign_bytes":
            data = bytes(bytearray(data))
        elif change == "changed_bytes":
            data = data[:-1] + b"X"
        elif change == "row_identity":
            list.__setitem__(pe.net.mdtables.ManifestResource.rows, 0, None)
        elif change == "limits":
            maximum = 1
        elif change == "heap_bytes":
            pe.net.strings.__data__ = b"X" + pe.net.strings.__data__[1:]
        else:
            pe.net.struct.ResourcesSize += 1
        resolver, work = factory.resolver_from_resource_snapshot(pe, data=data, row_snapshot=resource_view_scan._row_snapshot, max_rows=maximum)
        assert resolver.coverage()["complete"] is False
        assert work["accepted"] is False and work["unique_rows_reserved_this_resolver"] == 0
        assert resolver.resolve(0x06000001)["status"] == "unresolved"
    finally:
        pe.close()


def test_resource_portable_factory_never_promotes_simple_namespace_view_to_source_bound():
    data, pe = resource_view_fixture()
    resource_view_scan = resources.describe_clr_resources(data, pe)
    assert resource_view_scan.coverage()["inventory_complete"] is True and resource_view_scan.coverage()["parser_view_only"] is True
    resolver, work = factory.resolver_from_resource_snapshot(pe, data=data, row_snapshot=resource_view_scan._row_snapshot)
    assert resolver.coverage()["complete"] is False and work["accepted"] is False


@pytest.mark.parametrize("which", ["import_name", "setter", "allocator"])
def test_resource_portable_fixed_class_and_allocator_identity_cannot_be_replaced(monkeypatch, which):
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append("synthetic_unknown_class_hook")
        raise AssertionError("未知class hookを呼んではいけません")

    if which == "import_name":
        class UnreviewedResolver:
            pass
        monkeypatch.setattr(factory, "MetadataResolver", UnreviewedResolver)
    elif which == "setter":
        monkeypatch.setattr(factory.MetadataResolver, "__setattr__", forbidden)
    else:
        monkeypatch.setattr(factory.MetadataResolver, "__new__", staticmethod(forbidden))
    with pytest.raises(ValueError, match="shared_resolver_class_identity_invalid"):
        factory.resolver_from_resource_snapshot(None, data=b"", row_snapshot=None)
    assert calls == []
