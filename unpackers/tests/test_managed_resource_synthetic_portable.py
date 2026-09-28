"""人工生成bytesのみをdnfileで静的パースするCLR resource互換fixture。

全byteはこのsource内の定数、struct.pack、ゼロpaddingから新規生成する。
検体、OS binary、外部file、network、compilerを入力にしない。MethodDef、
CIL本文、PE/CLR entrypointは持たず、CLR runtime上の実行可能性は検証しない。
dnPEのdata入口だけを用い、resource本文の解釈やmanaged codeの実行もしない。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import struct

import pytest

from unpackers.tests.test_managed_resource_consumers_portable import ROOT as RESOURCE_ROOT, RESOURCE_NAMESPACE
import importlib
managed_resources = importlib.import_module(RESOURCE_NAMESPACE + ".managed_resources")

dnfile = pytest.importorskip("dnfile")

PRIVATE_NAME = "SYNTHETIC_PRIVATE_RESOURCE_NAME_ONLY"
PRIVATE_BODY = b"SYNTHETIC_PRIVATE_RESOURCE_BODY_ONLY\x00\xfe\xff"
LINK_NAME = "SYNTHETIC_LINK_SCOPE_NAME_ONLY"
SECTION_RVA = 0x2000
SECTION_FILE_OFFSET = 0x200
SECTION_SIZE = 0x600
CLR_FILE_OFFSET = SECTION_FILE_OFFSET
METADATA_FILE_OFFSET = 0x300
RESOURCE_FILE_OFFSET = 0x600


@dataclass(frozen=True)
class ResourcePortableSyntheticPE:
    """通常testだけで使う不変な人工入力。外部pathや観測値は含まない。"""

    data: bytes
    name: str
    body: bytes
    scope: str | None
    body_file_offset: int | None


def _resource_u16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def _resource_u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _resource_padding(data: bytes, alignment: int) -> bytes:
    return data + b"\x00" * (-len(data) % alignment)


def _resource_insert(data: bytes, offset: int, chunk: bytes) -> bytes:
    assert type(data) is bytes and type(chunk) is bytes
    assert 0 <= offset <= offset + len(chunk) <= len(data)
    return data[:offset] + chunk + data[offset + len(chunk):]


def _resource_rva(offset: int) -> int:
    return SECTION_RVA + offset - SECTION_FILE_OFFSET


def resource_build_synthetic_resource_pe(*, scope: str | None = None, linked_rid: int = 1,
                                declared_body_size: int | None = None) -> ResourcePortableSyntheticPE:
    """人工PE32と最小metadataを組立てる。実binaryのコピーやpatchではない。"""
    assert scope in (None, "File", "AssemblyRef")
    strings = b"\x00" + PRIVATE_NAME.encode("ascii") + b"\x00"
    link_name_index = len(strings)
    strings += LINK_NAME.encode("ascii") + b"\x00"
    implementation = 0
    table_rows: dict[int, bytes] = {}
    if scope == "File":
        # File: Flags、Name string index、HashValue blob index。
        table_rows[38] = struct.pack("<IHH", 0, link_name_index, 0)
        implementation = linked_rid << 2
    elif scope == "AssemblyRef":
        # AssemblyRef: version、Flags、PublicKeyOrToken、Name、Culture、HashValue。
        table_rows[35] = struct.pack("<HHHHIHHHH", 1, 0, 0, 0, 0, 0, link_name_index, 0, 0)
        implementation = (linked_rid << 2) | 1
    table_rows[40] = struct.pack("<IIHH", 0, 1, 1, implementation)
    table_numbers = tuple(sorted(table_rows))
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1,
                         sum(1 << number for number in table_numbers), 0)
    tables += b"".join(_resource_u32(1) for _ in table_numbers)
    tables += b"".join(table_rows[number] for number in table_numbers)
    version = _resource_padding(b"v4.0.30319\x00", 4)
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version))
    root += version + struct.pack("<HH", 0, 2)
    table_name = _resource_padding(b"#~\x00", 4)
    strings_name = _resource_padding(b"#Strings\x00", 4)
    stream_headers_size = 16 + len(table_name) + len(strings_name)
    table_offset = len(root) + stream_headers_size
    strings_offset = table_offset + len(tables)
    root += struct.pack("<II", table_offset, len(tables)) + table_name
    root += struct.pack("<II", strings_offset, len(strings)) + strings_name
    metadata = root + tables + strings
    assert METADATA_FILE_OFFSET + len(metadata) < RESOURCE_FILE_OFFSET

    body = PRIVATE_BODY if scope is None else b""
    size = len(body) if declared_body_size is None else declared_body_size
    resource_view_row = _resource_u32(size) + body if scope is None else b""
    resource_rva = _resource_rva(RESOURCE_FILE_OFFSET) if resource_view_row else 0
    clr = struct.pack("<IHH", 72, 2, 5)
    clr += b"".join(_resource_u32(value) for value in (
        _resource_rva(METADATA_FILE_OFFSET), len(metadata), 1, 0,
        resource_rva, len(resource_view_row), *([0] * 10),
    ))
    assert len(clr) == 72

    # PE32 optional header。entrypoint/code sizeは0で、sectionも実行属性を持たない。
    optional = _resource_u16(0x10B) + b"\x00\x00"
    optional += b"".join(_resource_u32(value) for value in (
        0, SECTION_SIZE, 0, 0, 0, SECTION_RVA, 0x400000, 0x1000, 0x200,
    ))
    optional += struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0)
    optional += struct.pack("<IIIIHH", 0, 0x3000, SECTION_FILE_OFFSET, 0, 3, 0)
    optional += b"".join(_resource_u32(value) for value in (
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ))
    assert len(optional) == 96
    optional += b"\x00" * (14 * 8)
    optional += struct.pack("<II", _resource_rva(CLR_FILE_OFFSET), len(clr)) + b"\x00" * 8
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(optional), 0x2102)
    section = struct.pack("<8sIIIIIIHHI", b".fixture", SECTION_SIZE, SECTION_RVA,
                          SECTION_SIZE, SECTION_FILE_OFFSET, 0, 0, 0, 0, 0x40000040)
    image = b"\x00" * (SECTION_FILE_OFFSET + SECTION_SIZE)
    image = _resource_insert(image, 0, b"MZ")
    image = _resource_insert(image, 0x3C, _resource_u32(0x80))
    image = _resource_insert(image, 0x80, b"PE\x00\x00" + coff + optional + section)
    image = _resource_insert(image, CLR_FILE_OFFSET, clr)
    image = _resource_insert(image, METADATA_FILE_OFFSET, metadata)
    image = _resource_insert(image, RESOURCE_FILE_OFFSET, resource_view_row)
    return ResourcePortableSyntheticPE(image, PRIVATE_NAME, body, scope,
                               RESOURCE_FILE_OFFSET + 4 if resource_view_row else None)


def _resource_parse_with_guard(resource_view_fixture: ResourcePortableSyntheticPE, monkeypatch):
    # 名前付きfileを渡さず、不変な人工bytesだけを静的parserへ渡す。
    pe = dnfile.dnPE(data=resource_view_fixture.data, clr_lazy_load=True)
    assert pe.net is not None and pe.net.mdtables is not None
    assert pe.net.mdtables._loaded is False and pe.net._resources is None
    calls: list[str] = []

    def reject_resource_contents(*_args, **_kwargs):
        calls.append("resource_contents_loader")
        raise AssertionError("人工fixtureのresource本文loaderを呼んではいけません")

    monkeypatch.setattr(type(pe.net), "_init_resources", reject_resource_contents)
    return pe, calls


def _resource_assert_public_projection_is_private(resource_view_scan, resource_view_fixture: ResourcePortableSyntheticPE) -> None:
    projections = [resource_view_scan.coverage(), resource_view_scan.__getstate__(), resource_view_scan._row_snapshot.__getstate__()]
    projections.extend(item.__getstate__() for item in resource_view_scan._descriptors)
    public_text = json.dumps(projections, ensure_ascii=False, sort_keys=True)
    public_text += repr(resource_view_scan) + repr(resource_view_scan._row_snapshot) + repr(resource_view_scan._descriptors)
    assert resource_view_fixture.name not in public_text
    assert PRIVATE_BODY[:-3].decode("ascii") not in public_text
    assert LINK_NAME not in public_text


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_portable_fixture_is_generated_data_without_methods_or_entrypoints(scope, monkeypatch):
    resource_view_fixture = resource_build_synthetic_resource_pe(scope=scope)
    assert type(resource_view_fixture.data) is bytes and len(resource_view_fixture.data) == 0x800
    assert resource_view_fixture.data == resource_build_synthetic_resource_pe(scope=scope).data
    pe, calls = _resource_parse_with_guard(resource_view_fixture, monkeypatch)
    try:
        assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0
        assert pe.net.struct.EntryPointTokenOrRva == 0
        assert pe.sections[0].Characteristics & 0x20000000 == 0
        assert pe.net.mdtables.MethodDef is None
        expected_tables = {40} | ({38} if scope == "File" else {35} if scope == "AssemblyRef" else set())
        assert set(pe.net.mdtables.tables) == expected_tables
        assert pe.net.mdtables.ManifestResource.num_rows == 1
        row = pe.net.mdtables.ManifestResource.rows[0]
        assert row.struct.Implementation_CodedIndex == {None: 0, "File": 4, "AssemblyRef": 5}[scope]
        assert row.struct.Offset == 0
        assert "Implementation" not in vars(row)
        assert pe.net.mdtables._loaded is False and calls == []
    finally:
        pe.close()


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_portable_dnfile_lazy_resource_inventory_without_full_loader(scope, monkeypatch):
    resource_view_fixture = resource_build_synthetic_resource_pe(scope=scope)
    pe, calls = _resource_parse_with_guard(resource_view_fixture, monkeypatch)
    try:
        resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        coverage = resource_view_scan.coverage()
        assert calls == []
        assert pe.net.mdtables._loaded is False and pe.net._resources is None
        assert "Implementation" not in vars(pe.net.mdtables.ManifestResource.rows[0])
        assert coverage["status"] == "complete", coverage["reason_counts"]
        assert coverage["counts"]["declared_resources"] == 1
        assert coverage["counts"]["embedded_resources"] == (scope is None)
        assert coverage["counts"]["linked_resources"] == (scope is not None)
        assert coverage["counts"]["descriptors_retained"] == 1
        assert coverage["counts"]["validated_resource_bytes"] == len(resource_view_fixture.body)
        descriptor = resource_view_scan._descriptors[0]
        assert descriptor.name == resource_view_fixture.name
        assert descriptor.body_offset == resource_view_fixture.body_file_offset
        if scope is None:
            assert descriptor.body_size == len(resource_view_fixture.body)
            assert resource_view_fixture.data[descriptor.body_offset:descriptor.body_offset + descriptor.body_size] == resource_view_fixture.body
        else:
            assert descriptor.body_size is None and descriptor.linked_scope == scope
        _resource_assert_public_projection_is_private(resource_view_scan, resource_view_fixture)
    finally:
        pe.close()


def test_resource_portable_unknown_full_loader_callback_is_rejected_without_calling_it(monkeypatch):
    resource_view_fixture = resource_build_synthetic_resource_pe()
    pe, calls = _resource_parse_with_guard(resource_view_fixture, monkeypatch)

    def reject_unknown_full_loader():
        calls.append("unknown_full_loader")
        raise AssertionError("未知callbackを呼んではいけません")

    monkeypatch.setattr(pe.net.mdtables.ManifestResource, "_full_loader", reject_unknown_full_loader)
    try:
        resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        coverage = resource_view_scan.coverage()
        assert calls == []
        assert coverage["status"] == "partial"
        assert coverage["counts"]["descriptors_retained"] == 0
        assert set(coverage["reason_counts"]) <= managed_resources.REASONS
        assert pe.net.mdtables._loaded is False and pe.net._resources is None
        _resource_assert_public_projection_is_private(resource_view_scan, resource_view_fixture)
    finally:
        pe.close()


def test_resource_portable_dnfile_resource_body_size_outside_directory_is_rejected(monkeypatch):
    resource_view_fixture = resource_build_synthetic_resource_pe(declared_body_size=len(PRIVATE_BODY) + 1)
    pe, calls = _resource_parse_with_guard(resource_view_fixture, monkeypatch)
    try:
        resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        coverage = resource_view_scan.coverage()
        assert calls == [] and pe.net.mdtables._loaded is False
        assert coverage["status"] == "partial"
        assert "resource_body_outside_directory" in coverage["reason_counts"]
        assert coverage["counts"]["descriptors_retained"] == 0
        _resource_assert_public_projection_is_private(resource_view_scan, resource_view_fixture)
    finally:
        pe.close()


@pytest.mark.parametrize("scope", ["File", "AssemblyRef"])
def test_resource_portable_dnfile_linked_rid_outside_same_pe_table_is_rejected(scope, monkeypatch):
    resource_view_fixture = resource_build_synthetic_resource_pe(scope=scope, linked_rid=2)
    pe, calls = _resource_parse_with_guard(resource_view_fixture, monkeypatch)
    try:
        resource_view_scan = managed_resources.describe_clr_resources(resource_view_fixture.data, pe)
        coverage = resource_view_scan.coverage()
        assert calls == [] and pe.net.mdtables._loaded is False
        assert coverage["status"] == "partial"
        assert "linked_reference_rid_invalid" in coverage["reason_counts"]
        assert coverage["counts"]["descriptors_retained"] == 0
        _resource_assert_public_projection_is_private(resource_view_scan, resource_view_fixture)
    finally:
        pe.close()
