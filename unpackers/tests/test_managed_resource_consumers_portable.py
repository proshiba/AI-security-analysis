"""production consumer最小接続の全人工PE・静的parser互換試験。

全input byteは定数、struct.pack、ゼロpaddingだけから生成する。検体、OS binary、
CLI入力、外部data、compiler、networkは使わない。MethodDef／CIL本文／entrypointを
持たないPEをresource_dnfileのdata入口で静的解釈するだけで、CLR/CIL/PEの実行はしない。
通常sourceの固定欄を人工goldenで確認し、検証不能時は明示partialとする。
私有path、旧baseline import、source pinに依存しない。
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import hashlib
import importlib
import math
import json
from pathlib import Path
import struct
import sys
from types import ModuleType, SimpleNamespace

import pytest

resource_dnfile = pytest.importorskip("dnfile")
def _resource_root():
    for ancestor in Path(__file__).resolve().parents:
        if ((ancestor / "unpackers" / "managed_resource_snapshot.py").is_file()
                and (ancestor / "analysis-framework").is_dir()):
            return ancestor
    raise RuntimeError("通常resource consumer sourceのancestorが見つかりません")


ROOT = _resource_root()
# checkoutのlabelはmodule衝突回避だけに用いる。source/audit cacheのkeyではない。
RESOURCE_NAMESPACE = "_resource_consumers_portable_" + hashlib.sha256(str(ROOT).encode("utf-8")).hexdigest()[:16]
resource_package = ModuleType(RESOURCE_NAMESPACE)
resource_package.__path__ = [str(ROOT / "unpackers")]
sys.modules[RESOURCE_NAMESPACE] = resource_package
resource_triage = importlib.import_module(RESOURCE_NAMESPACE + ".managed_il_triage")
resource_proxy = importlib.import_module(RESOURCE_NAMESPACE + ".managed_proxy_deobfuscator")
resource_snapshot = importlib.import_module(RESOURCE_NAMESPACE + ".managed_resource_snapshot")


RESOURCE_PRIVATE_NAME = "SYNTHETIC_PRIVATE_RESOURCE_NAME_ONLY"
RESOURCE_PRIVATE_BODY = b"SYNTHETIC_PRIVATE_RESOURCE_BODY_ONLY\x00\xfe\xff"
RESOURCE_LINK_NAME = "SYNTHETIC_LINK_SCOPE_NAME_ONLY"
RESOURCE_SECTION_RVA = 0x2000
RESOURCE_SECTION_FILE_OFFSET = 0x200
RESOURCE_SECTION_SIZE = 0x600
RESOURCE_CLR_FILE_OFFSET = RESOURCE_SECTION_FILE_OFFSET
RESOURCE_METADATA_FILE_OFFSET = 0x300
RESOURCE_BODY_FILE_OFFSET = 0x600


@dataclass(frozen=True)
class ResourceSyntheticPE:
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
    return RESOURCE_SECTION_RVA + offset - RESOURCE_SECTION_FILE_OFFSET


def resource_build_synthetic_resource_pe(*, scope: str | None = None, linked_rid: int = 1,
                                declared_body_size: int | None = None, include_resource: bool = True,
                                include_empty_type: bool = False) -> ResourceSyntheticPE:
    """人工PE32と最小metadataを組立てる。実binaryのコピーやpatchではない。"""
    assert scope in (None, "File", "AssemblyRef")
    strings = b"\x00" + RESOURCE_PRIVATE_NAME.encode("ascii") + b"\x00"
    link_name_index = len(strings)
    strings += RESOURCE_LINK_NAME.encode("ascii") + b"\x00"
    implementation = 0
    table_rows: dict[int, bytes] = {}
    if include_empty_type:
        # TypeDefだけを追加し、Field／Methodの空list indexを1にする。CIL本文は作らない。
        table_rows[2] = struct.pack("<IHHHHH", 0, 1, 0, 0, 1, 1)
    if scope == "File":
        # File: Flags、Name string index、HashValue blob index。
        table_rows[38] = struct.pack("<IHH", 0, link_name_index, 0)
        implementation = linked_rid << 2
    elif scope == "AssemblyRef":
        # AssemblyRef: version、Flags、PublicKeyOrToken、Name、Culture、HashValue。
        table_rows[35] = struct.pack("<HHHHIHHHH", 1, 0, 0, 0, 0, 0, link_name_index, 0, 0)
        implementation = (linked_rid << 2) | 1
    if include_resource:
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
    assert RESOURCE_METADATA_FILE_OFFSET + len(metadata) < RESOURCE_BODY_FILE_OFFSET

    body = RESOURCE_PRIVATE_BODY if scope is None and include_resource else b""
    size = len(body) if declared_body_size is None else declared_body_size
    resource = _resource_u32(size) + body if scope is None and include_resource else b""
    resource_rva = _resource_rva(RESOURCE_BODY_FILE_OFFSET) if resource else 0
    clr = struct.pack("<IHH", 72, 2, 5)
    clr += b"".join(_resource_u32(value) for value in (
        _resource_rva(RESOURCE_METADATA_FILE_OFFSET), len(metadata), 1, 0,
        resource_rva, len(resource), *([0] * 10),
    ))
    assert len(clr) == 72

    # PE32 optional header。entrypoint/code sizeは0で、sectionも実行属性を持たない。
    optional = _resource_u16(0x10B) + b"\x00\x00"
    optional += b"".join(_resource_u32(value) for value in (
        0, RESOURCE_SECTION_SIZE, 0, 0, 0, RESOURCE_SECTION_RVA, 0x400000, 0x1000, 0x200,
    ))
    optional += struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0)
    optional += struct.pack("<IIIIHH", 0, 0x3000, RESOURCE_SECTION_FILE_OFFSET, 0, 3, 0)
    optional += b"".join(_resource_u32(value) for value in (
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ))
    assert len(optional) == 96
    optional += b"\x00" * (14 * 8)
    optional += struct.pack("<II", _resource_rva(RESOURCE_CLR_FILE_OFFSET), len(clr)) + b"\x00" * 8
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(optional), 0x2102)
    section = struct.pack("<8sIIIIIIHHI", b".fixture", RESOURCE_SECTION_SIZE, RESOURCE_SECTION_RVA,
                          RESOURCE_SECTION_SIZE, RESOURCE_SECTION_FILE_OFFSET, 0, 0, 0, 0, 0x40000040)
    image = b"\x00" * (RESOURCE_SECTION_FILE_OFFSET + RESOURCE_SECTION_SIZE)
    image = _resource_insert(image, 0, b"MZ")
    image = _resource_insert(image, 0x3C, _resource_u32(0x80))
    image = _resource_insert(image, 0x80, b"PE\x00\x00" + coff + optional + section)
    image = _resource_insert(image, RESOURCE_CLR_FILE_OFFSET, clr)
    image = _resource_insert(image, RESOURCE_METADATA_FILE_OFFSET, metadata)
    image = _resource_insert(image, RESOURCE_BODY_FILE_OFFSET, resource)
    return ResourceSyntheticPE(image, RESOURCE_PRIVATE_NAME, body, scope,
                               RESOURCE_BODY_FILE_OFFSET + 4 if resource else None)



def _resource_golden_entropy():
    size = len(RESOURCE_PRIVATE_BODY)
    return round(-sum(count / size * math.log2(count / size) for count in Counter(RESOURCE_PRIVATE_BODY).values()), 4)


def _resource_golden_inventory(scope):
    linked = scope is not None
    return [{"index": 1, "name": RESOURCE_PRIVATE_NAME, "kind": "external" if linked else "internal",
             "declared_size": None if linked else len(RESOURCE_PRIVATE_BODY),
             "sha256": None if linked else hashlib.sha256(RESOURCE_PRIVATE_BODY).hexdigest(),
             "entropy": None if linked else _resource_golden_entropy(),
             "status": "external_reference" if linked else "hashed_full_resource"}]


def _resource_golden_counts(scope, *, with_type=False):
    result = {key: 0 for key in ("types_declared", "types_enumerated", "methods_declared",
        "methods_enumerated", "methods_with_body", "methods_parsed", "methods_without_body",
        "malformed_method_bodies", "instructions_counted", "branches", "switches", "switch_targets",
        "calls", "calli", "ldstr", "constant_loads", "proxy_method_candidates")}
    if with_type:
        result.update(types_declared=1, types_enumerated=1)
    result.update(resources_declared=1, resources_enumerated=1,
                  resource_bytes_hashed=len(RESOURCE_PRIVATE_BODY) if scope is None else 0)
    return result


@pytest.fixture
def resource_artificial_pe_factory():
    """兄弟testから固有名で取得できる、全人工bytes builderだけのprovider。"""
    return resource_build_synthetic_resource_pe


@pytest.fixture
def resource_static_parser_guard(monkeypatch):
    """新resource経路で旧RVA fallbackとresource本文loaderを呼ばない。"""
    real_parser = resource_dnfile.dnPE
    parsed, calls = [], []

    def reject_resources(*_args, **_kwargs):
        calls.append("resource_contents_loader")
        raise AssertionError("resource本文loaderは許可しない")

    def parser(*args, **kwargs):
        assert not args and type(kwargs["data"]) is bytes
        pe = real_parser(**kwargs)
        parsed.append(pe)
        if pe.net is not None:
            monkeypatch.setattr(type(pe.net), "_init_resources", reject_resources)
            def reject_rva(*_args, **_kwargs):
                calls.append("resource_rva_fallback")
                raise AssertionError("旧resource RVA fallbackは許可しない")
            monkeypatch.setattr(pe, "get_offset_from_rva", reject_rva)
        return pe

    monkeypatch.setattr(resource_dnfile, "dnPE", parser)
    yield parsed, calls
    for pe in parsed:
        pe.close()


def _resource_public_coverage_is_safe(result):
    coverage = result["resource_coverage"]
    text = json.dumps(coverage, sort_keys=True)
    assert RESOURCE_PRIVATE_NAME not in text and RESOURCE_LINK_NAME not in text
    assert RESOURCE_PRIVATE_BODY[:-3].decode("ascii") not in json.dumps(result)
    assert result["executed"] is result["emulated"] is result["clr_loaded"] is False
    assert result["network_contacted"] is False


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_normal_triage_resource_fields_match_golden(scope):
    fixture = resource_build_synthetic_resource_pe(scope=scope)
    new = resource_triage.analyze_managed_pe(fixture.data)
    assert new["resources"] == _resource_golden_inventory(scope)
    assert new["counts"] == _resource_golden_counts(scope)
    assert new["status"] == "analyzed"
    assert new["resource_coverage"]["inventory_complete"] is True
    assert new["reference_metadata_coverage"]["shared_snapshot"]["accepted"] is True
    assert new["reference_metadata_coverage"]["shared_snapshot"]["unique_rows_reserved_this_resolver"] == 0
    assert new["reference_metadata_coverage"]["shared_snapshot"]["resource_consumer_source_work"] == new["resource_coverage"]["work"]
    _resource_public_coverage_is_safe(new)

@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_normal_proxy_resource_fields_match_golden(scope):
    fixture = resource_build_synthetic_resource_pe(scope=scope)
    new = resource_proxy.analyze_managed_protector(fixture.data)
    expected = [] if scope else [{"name": RESOURCE_PRIVATE_NAME, "size": len(RESOURCE_PRIVATE_BODY),
        "sha256": hashlib.sha256(RESOURCE_PRIVATE_BODY).hexdigest(), "entropy": _resource_golden_entropy(),
        "protected_candidate": False}]
    assert new["resource_inventory"] == expected
    assert new["status"] == "no_match"
    assert new["proxy_analysis"]["candidates"] == []
    assert new["resource_coverage"]["inventory_complete"] is True
    assert new["proxy_analysis"]["metadata_coverage"] == new["reference_metadata_coverage"]
    assert new["reference_metadata_coverage"]["shared_snapshot"]["resource_consumer_source_work"] == new["resource_coverage"]["work"]
    _resource_public_coverage_is_safe(new)

@pytest.mark.parametrize("consumer", [resource_triage.analyze_managed_pe, resource_proxy.analyze_managed_protector])
@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_artificial_positive_static_only_without_resource_loaders(consumer, scope, resource_static_parser_guard):
    fixture = resource_build_synthetic_resource_pe(scope=scope)
    result = consumer(fixture.data)
    parsed, calls = resource_static_parser_guard
    assert result["status"] in {"analyzed", "no_match"}, result
    assert calls == []
    assert parsed[0].net.mdtables._loaded is False
    assert "Implementation" not in vars(parsed[0].net.mdtables.ManifestResource.rows[0])
    _resource_public_coverage_is_safe(result)


@pytest.mark.parametrize("consumer", [resource_triage.analyze_managed_pe, resource_proxy.analyze_managed_protector])
def test_resource_absent_resource_is_complete_empty_not_partial(consumer, resource_static_parser_guard):
    fixture = resource_build_synthetic_resource_pe(include_resource=False)
    result = consumer(fixture.data)
    assert result["status"] in {"analyzed", "no_match"}, result
    assert result["resource_coverage"]["counts"]["declared_resources"] == 0
    assert result["resource_coverage"]["inventory_complete"] is True
    assert result.get("resources", result.get("resource_inventory")) == []
    assert resource_static_parser_guard[1] == []


@pytest.mark.parametrize("consumer,partial", [(resource_triage.analyze_managed_pe, "analyzed_partial_budget"),
                                              (resource_proxy.analyze_managed_protector, "partial_budget")])
def test_resource_malformed_resource_cannot_be_no_match_or_complete(consumer, partial, resource_static_parser_guard):
    fixture = resource_build_synthetic_resource_pe(declared_body_size=len(RESOURCE_PRIVATE_BODY) + 1)
    result = consumer(fixture.data)
    assert result["status"] == partial, result
    assert result["resource_coverage"]["inventory_complete"] is False
    assert result.get("resources", result.get("resource_inventory")) == []
    if result.get("proxy_analysis"):
        assert result["proxy_analysis"]["status"] == "partial_budget"
        assert result["proxy_analysis"]["candidates"] == []
    assert resource_static_parser_guard[1] == []


@pytest.mark.parametrize("module,partial", [(resource_triage, "analyzed_partial_budget"), (resource_proxy, "partial_budget")])
def test_resource_resource_byte_budget_is_top_partial(module, partial, monkeypatch, resource_static_parser_guard):
    fixture = resource_build_synthetic_resource_pe()
    if module is resource_triage:
        result = module.analyze_managed_pe(fixture.data, max_resource_bytes=1)
    else:
        monkeypatch.setattr(module, "MAX_RESOURCE_BYTES", 1)
        result = module.analyze_managed_protector(fixture.data)
    assert result["status"] == partial
    assert result["resource_coverage"]["inventory_complete"] is False
    assert result["resource_coverage"]["reason_counts"]["resource_byte_budget_exceeded"] == 1
    assert resource_static_parser_guard[1] == []


@pytest.mark.parametrize("module,partial", [(resource_triage, "analyzed_partial_budget"), (resource_proxy, "partial_budget")])
@pytest.mark.parametrize("mutation", ["section", "descriptor", "strings"])
def test_resource_changed_shared_source_or_descriptor_is_not_consumed(module, partial, mutation, monkeypatch, resource_static_parser_guard):
    fixture = resource_build_synthetic_resource_pe()
    real_prepare = module.prepare_resource_snapshot
    def prepare(data, pe, **kwargs):
        scan, resolver, work = real_prepare(data, pe, **kwargs)
        if mutation == "section":
            pe.sections[0].VirtualAddress += 1
        elif mutation == "descriptor":
            scan._descriptors[0].body_offset += 1
        else:
            heap = pe.net.metadata.streams[b"#Strings"]
            heap._data = b"X" + heap._data[1:]
        return scan, resolver, work
    monkeypatch.setattr(module, "prepare_resource_snapshot", prepare)
    result = (module.analyze_managed_pe(fixture.data) if module is resource_triage else module.analyze_managed_protector(fixture.data))
    assert result["status"] == partial, result
    assert result.get("resources", result.get("resource_inventory")) == []
    assert result["resource_coverage"]["inventory_complete"] is False
    assert resource_static_parser_guard[1] == []


@pytest.mark.parametrize("module,partial", [(resource_triage, "analyzed_partial_budget"), (resource_proxy, "partial_budget")])
@pytest.mark.parametrize("failure", ["missing_dependency", "factory_failure"])
def test_resource_new_snapshot_failure_is_closed_partial(module, partial, failure, monkeypatch, resource_static_parser_guard):
    if failure == "missing_dependency":
        monkeypatch.setattr(module, "prepare_resource_snapshot", None)
    else:
        def fail(*_args, **_kwargs):
            raise ValueError("人工のfactory失敗")
        monkeypatch.setattr(module, "prepare_resource_snapshot", fail)
    fixture = resource_build_synthetic_resource_pe()
    result = (module.analyze_managed_pe(fixture.data) if module is resource_triage else module.analyze_managed_protector(fixture.data))
    assert result["status"] == partial
    assert result["resource_coverage"]["reason_counts"] == {"resource_snapshot_preparation_failed": 1}
    assert result["reference_metadata_coverage"]["complete"] is False
    assert resource_static_parser_guard[1] == []


@pytest.mark.parametrize("kwargs", [{"max_resources": 4097}, {"max_resource_bytes": (64 << 20) + 1}])
def test_resource_new_resource_hard_limits_are_validated_before_parser(kwargs, monkeypatch):
    def fail(*_args, **_kwargs):
        raise AssertionError("hard上限違反はparserより前に拒否する")
    monkeypatch.setattr(resource_dnfile, "dnPE", fail)
    with pytest.raises(ValueError):
        resource_triage.analyze_managed_pe(resource_build_synthetic_resource_pe().data, **kwargs)


@pytest.mark.parametrize("module,partial", [(resource_triage, "analyzed_partial_budget"), (resource_proxy, "partial_budget")])
def test_resource_ordinary_mock_is_explicit_parser_view_only_partial(module, partial, monkeypatch):
    pe = SimpleNamespace(net=SimpleNamespace(struct=SimpleNamespace(ResourcesRva=0, ResourcesSize=0),
                                             mdtables=SimpleNamespace()))
    monkeypatch.setattr(resource_dnfile, "dnPE", lambda **_kwargs: pe)
    result = (module.analyze_managed_pe(b"") if module is resource_triage else module.analyze_managed_protector(b""))
    assert result["status"] == partial, result
    assert result["resource_coverage"]["input_binding_verified"] is False
    assert result["resource_coverage"]["inventory_complete"] is False


def test_resource_snapshot_precedes_first_type_owner_walk(monkeypatch, resource_static_parser_guard):
    fixture = resource_build_synthetic_resource_pe()
    events = []
    prepare = resource_triage.prepare_resource_snapshot
    table = resource_triage._table
    def tracked_prepare(*args, **kwargs):
        events.append("resource_snapshot")
        return prepare(*args, **kwargs)
    def tracked_table(pe, name):
        events.append(name)
        return table(pe, name)
    monkeypatch.setattr(resource_triage, "prepare_resource_snapshot", tracked_prepare)
    monkeypatch.setattr(resource_triage, "_table", tracked_table)
    result = resource_triage.analyze_managed_pe(fixture.data)
    assert result["status"] == "analyzed", result
    assert events[0] == "resource_snapshot" and events.index("resource_snapshot") < events.index("TypeDef")


@pytest.mark.parametrize("validated", [False, True])
def test_resource_proxy_candidate_never_becomes_confirmed_runtime_evidence(validated, monkeypatch):
    # 全recordは整数定数から作る。復号はnormal変換の実行ではなく合成stubに置換する。
    records = b"".join(struct.pack("<II", 0x04000001 + i, 0x06000001 + i) for i in range(8))
    monkeypatch.setattr(resource_proxy, "decrypt_eaz_proxy_table", lambda *_args, **_kwargs: records)
    resolver = None
    if validated:
        resolver = SimpleNamespace(resolve=lambda *_args, **_kwargs: {"status": "resolved"},
                                   coverage=lambda: {"complete": True})
    result = resource_proxy.analyze_proxy_resources([(RESOURCE_PRIVATE_NAME, b"S" * 64)], metadata_resolver=resolver)
    assert result["status"] == "matched" and len(result["candidates"]) == 1
    candidate = result["candidates"][0]
    assert candidate["validation_level"] == ("metadata_declaration_validated_candidate" if validated
                                              else "syntactic_candidate_only")
    assert candidate["runtime_dispatch_verified"] is False
    assert candidate["protector_attribution_confirmed"] is False


@pytest.mark.parametrize("consumer", [resource_triage.analyze_managed_pe, resource_proxy.analyze_managed_protector])
def test_resource_fixture_proves_no_methods_or_executable_entrypoint(consumer, resource_static_parser_guard):
    fixture = resource_build_synthetic_resource_pe()
    assert type(fixture.data) is bytes and fixture.data == resource_build_synthetic_resource_pe().data
    result = consumer(fixture.data)
    pe = resource_static_parser_guard[0][0]
    assert result["status"] in {"analyzed", "no_match"}
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0
    assert pe.net.struct.EntryPointTokenOrRva == 0
    assert pe.net.mdtables.MethodDef is None
    assert pe.sections[0].Characteristics & 0x20000000 == 0


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_normal_empty_type_owner_walk_matches_golden(scope):
    fixture = resource_build_synthetic_resource_pe(scope=scope, include_empty_type=True)
    new = resource_triage.analyze_managed_pe(fixture.data)
    assert new["status"] == "analyzed", new
    assert new["types"] == [{"token": "0x02000001", "namespace": "", "name": RESOURCE_PRIVATE_NAME,
                             "method_references": 0}]
    assert new["methods"] == new["static_references"] == []
    assert new["counts"] == _resource_golden_counts(scope, with_type=True)
    assert new["resources"] == _resource_golden_inventory(scope)
    assert new["resource_coverage"]["inventory_complete"] is True
    assert new["reference_metadata_coverage"]["shared_snapshot"]["accepted"] is True

def test_resource_second_triage_consume_exception_is_fixed_partial(monkeypatch, resource_static_parser_guard):
    def fail(*_args, **_kwargs):
        raise ValueError("人工のsecond consume失敗")
    monkeypatch.setattr(resource_triage, "_resource_inventory_scope", fail)
    result = resource_triage.analyze_managed_pe(resource_build_synthetic_resource_pe().data)
    assert result["status"] == "analyzed_partial_budget"
    assert result["resources"] == []
    assert result["resource_coverage"]["reason_counts"] == {"resource_consumer_revalidation_failed": 1}
    assert result["reference_metadata_coverage"]["complete"] is False
    assert resource_static_parser_guard[1] == []


@pytest.mark.parametrize("scope", [None, "File", "AssemblyRef"])
def test_resource_legacy_helper_shapes_are_preserved(scope, resource_static_parser_guard):
    fixture = resource_build_synthetic_resource_pe(scope=scope)
    pe = resource_dnfile.dnPE(data=fixture.data, clr_lazy_load=True)
    inventory = resource_triage._resource_inventory(fixture.data, pe, 1024, 64 << 20)
    assert type(inventory) is tuple and len(inventory) == 3
    assert inventory[2] == []
    blobs = resource_proxy._resource_blobs(fixture.data, pe)
    assert iter(blobs) is blobs
    assert list(blobs) == ([(RESOURCE_PRIVATE_NAME, RESOURCE_PRIVATE_BODY)] if scope is None else [])
    assert resource_static_parser_guard[1] == []
