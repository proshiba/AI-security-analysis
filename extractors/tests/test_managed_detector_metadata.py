"""欠落・破損CLR metadataで検出器を停止させず、偽の帰属を防ぐ。"""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from extractors.asyncrat import integrated as asyncrat
from extractors.managed_pe import has_clr_metadata
from extractors.purehvnc import extractor as purehvnc


def _managed_pe_fixture(metadata_signature: bytes = b"BSJB") -> bytes:
    """parserを実行せずにCLR directory境界だけを満たす最小PEを組み立てる。"""

    data = bytearray(0x600)
    data[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    coff_offset = pe_offset + 4
    struct.pack_into("<HHIIIHH", data, coff_offset, 0x14C, 1, 0, 0, 0, 0xE0, 0)
    optional_offset = coff_offset + 20
    struct.pack_into("<H", data, optional_offset, 0x10B)
    struct.pack_into("<I", data, optional_offset + 60, 0x200)
    struct.pack_into("<I", data, optional_offset + 92, 16)
    clr_entry = optional_offset + 96 + 14 * 8
    struct.pack_into("<II", data, clr_entry, 0x2000, 0x48)
    section_offset = optional_offset + 0xE0
    data[section_offset : section_offset + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section_offset + 8, 0x400, 0x2000, 0x400, 0x200)
    struct.pack_into("<I", data, 0x200, 0x48)
    struct.pack_into("<II", data, 0x208, 0x2100, 0x40)
    data[0x300 : 0x300 + len(metadata_signature)] = metadata_signature
    return bytes(data)


@pytest.mark.parametrize("net", [None, SimpleNamespace(user_strings=None), SimpleNamespace()])
def test_purerat_absent_user_string_heap_is_not_a_detector_error(monkeypatch, net):
    closed = []
    pe = SimpleNamespace(net=net, close=lambda: closed.append(True))
    monkeypatch.setattr(purehvnc.dnfile, "dnPE", lambda **_: pe)
    fixture = _managed_pe_fixture()
    assert list(purehvnc.iter_dotnet_user_strings(fixture)) == []
    assert closed == []
    with pytest.raises(ValueError, match="managed_user_strings_unavailable"):
        purehvnc.extract_managed_config(fixture)


@pytest.mark.parametrize("heap_size,raw_size", [(100, 2), (5, 5), (-1, 2)])
def test_purerat_out_of_range_heap_item_is_not_used(monkeypatch, heap_size, raw_size):
    closed = []
    item = SimpleNamespace(raw_size=raw_size, value="outside-heap")
    heap = SimpleNamespace(sizeof=lambda: heap_size, get=lambda *_, **__: item)
    pe = SimpleNamespace(net=SimpleNamespace(user_strings=heap), close=lambda: closed.append(True))
    monkeypatch.setattr(purehvnc.dnfile, "dnPE", lambda **_: pe)
    with pytest.raises(ValueError, match="user_string_"):
        list(purehvnc.iter_dotnet_user_strings(_managed_pe_fixture()))
    assert closed == []


def test_purerat_valid_user_strings_remain_available(monkeypatch):
    closed = []
    heap = SimpleNamespace(
        sizeof=lambda: 5,
        get=lambda offset, **_: SimpleNamespace(raw_size=2, value={1: "first", 3: "second"}[offset]),
    )
    pe = SimpleNamespace(net=SimpleNamespace(user_strings=heap), close=lambda: closed.append(True))
    monkeypatch.setattr(purehvnc.dnfile, "dnPE", lambda **_: pe)
    assert list(purehvnc.iter_dotnet_user_strings(_managed_pe_fixture())) == ["first", "second"]
    assert closed == []


def test_managed_pe_prefilter_rejects_native_or_invalid_metadata() -> None:
    """CLR directory、metadata RVA、BSJBの全境界が揃った場合だけ受理する。"""

    assert has_clr_metadata(_managed_pe_fixture()) is True
    assert has_clr_metadata(_managed_pe_fixture(b"NOPE")) is False
    assert has_clr_metadata(b"MZ fixture") is False


def test_managed_pe_prefilter_rejects_truncated_declared_clr_ranges() -> None:
    """CLR headerとmetadataの宣言範囲がraw sectionを越える入力を拒否する。"""

    undersized_directory = bytearray(_managed_pe_fixture())
    optional_offset = 0x80 + 4 + 20
    clr_entry = optional_offset + 96 + 14 * 8
    struct.pack_into("<I", undersized_directory, clr_entry + 4, 0x10)
    assert has_clr_metadata(bytes(undersized_directory)) is False

    undersized_header = bytearray(_managed_pe_fixture())
    struct.pack_into("<I", undersized_header, 0x200, 0x10)
    assert has_clr_metadata(bytes(undersized_header)) is False

    truncated_header = bytearray(_managed_pe_fixture())
    struct.pack_into("<I", truncated_header, clr_entry + 4, 0x500)
    struct.pack_into("<I", truncated_header, 0x200, 0x500)
    assert has_clr_metadata(bytes(truncated_header)) is False

    truncated_metadata = bytearray(_managed_pe_fixture())
    struct.pack_into("<I", truncated_metadata, 0x20C, 0x400)
    assert has_clr_metadata(bytes(truncated_metadata)) is False


def test_purerat_prefilter_skips_dnfile_for_non_managed_input(monkeypatch) -> None:
    """native PE候補には高コストなmetadata parserを起動しない。"""

    monkeypatch.setattr(
        purehvnc.dnfile,
        "dnPE",
        lambda **_: pytest.fail("非managed入力でdnfileを呼んではならない"),
    )
    assert list(purehvnc.iter_dotnet_user_strings(_managed_pe_fixture(b"NOPE"))) == []


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
