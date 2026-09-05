"""欠落・破損CLR metadataで検出器を停止させず、偽の帰属を防ぐ。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from extractors.asyncrat import integrated as asyncrat
from extractors.purehvnc import extractor as purehvnc


@pytest.mark.parametrize("net", [None, SimpleNamespace(user_strings=None), SimpleNamespace()])
def test_purerat_absent_user_string_heap_is_not_a_detector_error(monkeypatch, net):
    closed = []
    pe = SimpleNamespace(net=net, close=lambda: closed.append(True))
    monkeypatch.setattr(purehvnc.dnfile, "dnPE", lambda **_: pe)
    assert list(purehvnc.iter_dotnet_user_strings(b"MZ fixture")) == []
    assert closed == []
    with pytest.raises(ValueError, match="managed_user_strings_unavailable"):
        purehvnc.extract_managed_config(b"MZ fixture")


@pytest.mark.parametrize("heap_size,raw_size", [(100, 2), (5, 5), (-1, 2)])
def test_purerat_out_of_range_heap_item_is_not_used(monkeypatch, heap_size, raw_size):
    closed = []
    item = SimpleNamespace(raw_size=raw_size, value="outside-heap")
    heap = SimpleNamespace(sizeof=lambda: heap_size, get=lambda *_, **__: item)
    pe = SimpleNamespace(net=SimpleNamespace(user_strings=heap), close=lambda: closed.append(True))
    monkeypatch.setattr(purehvnc.dnfile, "dnPE", lambda **_: pe)
    with pytest.raises(ValueError, match="user_string_"):
        list(purehvnc.iter_dotnet_user_strings(b"MZ fixture"))
    assert closed == []


def test_purerat_valid_user_strings_remain_available(monkeypatch):
    closed = []
    heap = SimpleNamespace(
        sizeof=lambda: 5,
        get=lambda offset, **_: SimpleNamespace(raw_size=2, value={1: "first", 3: "second"}[offset]),
    )
    pe = SimpleNamespace(net=SimpleNamespace(user_strings=heap), close=lambda: closed.append(True))
    monkeypatch.setattr(purehvnc.dnfile, "dnPE", lambda **_: pe)
    assert list(purehvnc.iter_dotnet_user_strings(b"MZ fixture")) == ["first", "second"]
    assert closed == []


def _asyncrat_metadata():
    methods = []
    types = []
    fields = [SimpleNamespace(Name=name) for name in sorted(asyncrat._SETTINGS)]
    for owner, required in asyncrat._REQUIRED_METHODS.items():
        method_refs = []
        for name in sorted(required):
            methods.append(SimpleNamespace(Name=name))
            method_refs.append(SimpleNamespace(row_index=len(methods)))
        namespace, _, name = owner.rpartition(".")
        types.append(SimpleNamespace(
            TypeNamespace=namespace,
            TypeName=name,
            MethodList=method_refs,
            FieldList=[SimpleNamespace(row_index=index + 1) for index in range(len(fields))],
        ))
    return SimpleNamespace(
        TypeDef=SimpleNamespace(rows=types),
        MethodDef=SimpleNamespace(rows=methods),
        Field=SimpleNamespace(rows=fields),
    )


def _asyncrat_evidence(monkeypatch, tables):
    closed = []
    pe = SimpleNamespace(net=SimpleNamespace(mdtables=tables), close=lambda: closed.append(True))
    monkeypatch.setattr(asyncrat.dnfile, "dnPE", lambda **_: pe)
    fixture = b"MZ\0BSJB\0" + b"\0".join(value.encode() for value in asyncrat._PROTOCOL) + b"\0"
    result = asyncrat.structural_evidence(fixture)
    assert closed == []
    return result


@pytest.mark.parametrize("missing", ["all", "TypeDef", "MethodDef", "Field"])
def test_asyncrat_absent_tables_fail_closed_without_detector_error(monkeypatch, missing):
    tables = _asyncrat_metadata()
    if missing == "all":
        tables = None
    else:
        setattr(tables, missing, None)
    result = _asyncrat_evidence(monkeypatch, tables)
    assert result["matched"] is False
    assert result["settings_fields_complete"] is False
    assert result["methods_complete"] is False
    assert result["metadata_status"] == "unavailable_or_invalid"
    assert result["metadata_error_type"] == "ValueError"


@pytest.mark.parametrize("table,index", [("MethodList", 0), ("MethodList", -1), ("MethodList", 999), ("FieldList", 0), ("FieldList", True)])
def test_asyncrat_invalid_metadata_reference_cannot_supply_family_evidence(monkeypatch, table, index):
    tables = _asyncrat_metadata()
    getattr(tables.TypeDef.rows[0], table)[0].row_index = index
    assert _asyncrat_evidence(monkeypatch, tables)["matched"] is False


def test_asyncrat_valid_structure_still_matches(monkeypatch):
    result = _asyncrat_evidence(monkeypatch, _asyncrat_metadata())
    assert result["matched"] is True
    assert result["settings_fields_complete"] is True
    assert result["methods_complete"] is True
    assert result["metadata_status"] == "parsed"
    assert result["metadata_error_type"] is None


def test_asyncrat_metadata_row_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(asyncrat, "MAX_METHODS", 2)
    assert _asyncrat_evidence(monkeypatch, _asyncrat_metadata())["matched"] is False
