"""trusted snapshotの辞書key改変は、未知hash/eqを呼ばずpartialへ拒否する。"""

import pytest

from unpackers.tests.test_managed_resource_input_portable import (
    resource_parser, resource_module_origin, managed_resources, resource_assert_complete, resource_assert_partial,
)


def resource_collision_marker(name, calls, *, semantic_match):
    # hash/eqは人工markerだけ。構築時の呼出しは試験の直前に記録を消去する。
    class Marker:
        def __hash__(self):
            calls.append("synthetic_unknown_hash_called")
            return hash(name)

        def __eq__(self, other):
            calls.append("synthetic_unknown_equality_called")
            return semantic_match and type(other) is type(name) and other == name

    return Marker()


@pytest.mark.parametrize("semantic_match", [False, True])
@pytest.mark.parametrize("mapping_name", ["rows", "tables", "sources", "states"])
def test_resource_portable_shared_top_level_keys_are_exact_fixed_strings_before_set_or_lookup(resource_parser, mapping_name, semantic_match):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    snapshot = first._row_snapshot
    mapping = getattr(snapshot, mapping_name)
    calls = []
    marker = resource_collision_marker("ManifestResource", calls, semantic_match=semantic_match)
    retained = mapping.pop("ManifestResource")
    mapping[marker] = retained
    assert len(mapping) == 13
    calls.clear()
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=snapshot)
    assert calls == []
    resource_assert_partial(resource_view_scan, resource_view_fixture)


@pytest.mark.parametrize("semantic_match", [False, True])
def test_resource_portable_shared_state_keys_are_exact_fixed_strings_before_get(resource_parser, semantic_match):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    snapshot = first._row_snapshot
    state = snapshot.states["ManifestResource"]
    calls = []
    marker = resource_collision_marker("present", calls, semantic_match=semantic_match)
    retained = state.pop("present")
    state[marker] = retained
    assert len(state) == 5
    calls.clear()
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=snapshot)
    assert calls == []
    resource_assert_partial(resource_view_scan, resource_view_fixture)


def test_resource_portable_unknown_ordinary_string_state_key_is_partial_without_callback(resource_parser):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    first._row_snapshot.states["ManifestResource"]["synthetic_unknown_state_key"] = None
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot)
    resource_assert_partial(resource_view_scan, resource_view_fixture)


@pytest.mark.parametrize("semantic_match", [False, True])
def test_resource_portable_shared_lazy_table_names_are_exact_strings_before_subset_or_membership(resource_parser, semantic_match):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    calls = []
    marker = resource_collision_marker("ManifestResource", calls, semantic_match=semantic_match)
    first._row_snapshot.lazy_tables = frozenset({marker})
    calls.clear()
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot)
    assert calls == []
    resource_assert_partial(resource_view_scan, resource_view_fixture)


@pytest.mark.parametrize("semantic_match", [False, True])
@pytest.mark.parametrize("registry_name", ["streams", "tables"])
def test_resource_portable_shared_parser_registry_keys_are_exact_before_lookup_or_set(resource_parser, registry_name, semantic_match):
    create, _hooks = resource_parser
    resource_view_fixture, pe = create()
    first = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
    resource_assert_complete(first, resource_view_fixture)
    if registry_name == "streams":
        registry, key = pe.net.metadata.streams, b"#Strings"
    else:
        registry, key = pe.net.mdtables.tables, 40
    calls = []
    marker = resource_collision_marker(key, calls, semantic_match=semantic_match)
    retained = registry.pop(key)
    registry[marker] = retained
    calls.clear()
    resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe, row_snapshot=first._row_snapshot)
    assert calls == []
    resource_assert_partial(resource_view_scan, resource_view_fixture)
