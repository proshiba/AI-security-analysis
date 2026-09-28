"""人工 PE の宣言 guard と constructor 前順序だけを確認する。実検体・runtimeなし。"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

import pytest
import dnfile

ROOT = next(item for item in Path(__file__).resolve().parents
            if (item / "unpackers" / "managed_constructor_guard.py").is_file())
assert (ROOT / "unpackers" / "managed_resource_snapshot.py").is_file()
sys.path.insert(0, str(ROOT))
from unpackers import managed_constructor_guard as guard
from unpackers import clr_input_binding as binding
from unpackers import managed_il_triage as triage
from unpackers import managed_proxy_deobfuscator as proxy
actual_constructor = dnfile.dnPE


def constructor_insert(data, offset, content):
    assert type(data) is bytes and type(content) is bytes
    assert 0 <= offset <= offset + len(content) <= len(data)
    return data[:offset] + content + data[offset + len(content):]


def constructor_build_pe(counts=None, *, payload=True, table_name=b"#~"):
    """全byteを定数、pack、ゼロpaddingで生成。entrypoint0、非実行section。"""
    counts = {} if counts is None else counts
    numbers = tuple(sorted(counts))
    all_counts = tuple(counts.get(number, 0) for number in range(64))
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, sum(1 << n for n in numbers), 0)
    tables += b"".join(struct.pack("<I", counts[n]) for n in numbers)
    if payload:
        tables += b"".join(bytes(binding._row_size(n, all_counts, (2, 2, 2)) * counts[n]) for n in numbers)
    version = b"v4.0.30319\0\0"
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, 2)
    padded_names = tuple(name + bytes(-len(name) % 4) for name in (table_name + b"\0", b"#Strings\0"))
    table_relative = len(root) + sum(8 + len(name) for name in padded_names)
    metadata = root + struct.pack("<II", table_relative, len(tables)) + padded_names[0]
    metadata += struct.pack("<II", table_relative + len(tables), 1) + padded_names[1] + tables + b"\0"
    size = (0x100 + len(metadata) + 0x1ff) // 0x200 * 0x200
    clr = struct.pack("<IHH", 72, 2, 5) + struct.pack("<IIII", 0x2100, len(metadata), 1, 0) + bytes(48)
    optional = struct.pack("<HBB", 0x10b, 0, 0)
    optional += struct.pack("<9I", 0, size, 0, 0, 0, 0x2000, 0x400000, 0x1000, 0x200)
    optional += struct.pack("<6H", 4, 0, 0, 0, 4, 0)
    optional += struct.pack("<4I2H", 0, (0x2000 + size + 0xfff) // 0x1000 * 0x1000, 0x200, 0, 3, 0)
    optional += struct.pack("<6I", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    assert len(optional) == 96
    optional += bytes(14 * 8) + struct.pack("<II", 0x2000, 72) + bytes(8)
    coff = struct.pack("<HHIIIHH", 0x14c, 1, 0, 0, 0, len(optional), 0x2102)
    section = struct.pack("<8sIIIIIIHHI", b".guard", size, 0x2000, size, 0x200, 0, 0, 0, 0, 0x40000040)
    data = bytes(0x200 + size)
    for offset, body in ((0, b"MZ"), (60, struct.pack("<I", 0x80)),
                         (0x80, b"PE\0\0" + coff + optional + section),
                         (0x200, clr), (0x300, metadata)):
        data = constructor_insert(data, offset, body)
    return data


def constructor_factory_counter(monkeypatch, module, *, real=False):
    calls = []
    def factory(**kwargs):
        calls.append(kwargs)
        if real:
            return actual_constructor(**kwargs)
        raise AssertionError("拒否入力で constructor を呼んではいけません")
    monkeypatch.setattr(module, "dnfile", SimpleNamespace(dnPE=factory, __version__=dnfile.__version__))
    return calls


@pytest.mark.parametrize("number", range(45))
def test_each_raw_table_limit_rejects_before_both_constructors(number, monkeypatch):
    data = constructor_build_pe({number: 20_001}, payload=False)
    outcome = guard.preflight_clr_declarations(data)
    assert outcome["reason_counts"] == {"preflight_metadata_table_row_budget": 1}
    for module, analyze, status in ((triage, triage.analyze_managed_pe, "analyzed_partial_budget"),
                                    (proxy, proxy.analyze_managed_protector, "partial_budget")):
        calls = constructor_factory_counter(monkeypatch, module)
        result = analyze(data)
        assert calls == []
        assert result["status"] == status
        assert result["metadata_preflight"] == outcome
        assert result["reference_metadata_coverage"]["shared_snapshot"]["accepted"] is False


@pytest.mark.parametrize("counts", [{n: 2_001 for n in range(45)},
                                    {0: 20_000, 2: 20_000, 6: 20_000, 33: 20_000, 34: 1}])
def test_total_all45_not_only_shared13_before_constructor(counts, monkeypatch):
    data = constructor_build_pe(counts, payload=False)
    for module, analyze in ((triage, triage.analyze_managed_pe), (proxy, proxy.analyze_managed_protector)):
        calls = constructor_factory_counter(monkeypatch, module)
        result = analyze(data)
        assert calls == []
        assert result["metadata_preflight"]["reason_counts"] == {"preflight_metadata_total_row_budget": 1}


@pytest.mark.parametrize("number", range(45))
def test_exact_per_table_boundary_validates_without_row_materialization(number):
    result = guard.preflight_clr_declarations(constructor_build_pe({number: 20_000}))
    assert result["accepted"] and result["counts"]["rows_declared"] == 20_000
    assert result["scope"] == "constructor_declarations_only"


def test_exact_total_boundary_validates_and_pointer_layout_not_family_rejected():
    counts = {0: 20_000, 3: 20_000, 5: 20_000, 7: 20_000}
    result = guard.preflight_clr_declarations(constructor_build_pe(counts))
    assert result["accepted"] and result["counts"]["rows_declared"] == 80_000


@pytest.mark.parametrize("value", [None, "MZ", bytearray(b"MZ"), memoryview(b"MZ")])
def test_exact_bytes_type_only(value):
    assert guard.preflight_clr_declarations(value)["reason_counts"] == {"preflight_input_type_invalid": 1}


def test_bytes_and_budget_subclasses_never_run_marker_callbacks():
    calls = []
    class MarkerBytes(bytes):
        def __len__(self):
            calls.append("len")
            raise AssertionError
        def __getitem__(self, _key):
            calls.append("getitem")
            raise AssertionError
    class MarkerInt(int):
        def __le__(self, _other):
            calls.append("le")
            raise AssertionError
    assert not guard.preflight_clr_declarations(MarkerBytes(b"MZ"))["accepted"]
    assert not guard.preflight_clr_declarations(b"MZ", max_table_rows=MarkerInt(1))["accepted"]
    assert calls == []


@pytest.mark.parametrize("name,limit", [("max_input_bytes", guard.MAX_INPUT_BYTES),
                                       ("max_table_rows", 20_000), ("max_total_rows", 80_000)])
@pytest.mark.parametrize("value", [False, 0, -1, 1.5, "1"])
def test_budget_types_and_down_only(name, limit, value):
    assert guard.preflight_clr_declarations(b"", **{name: value})["reason_counts"] == {"preflight_budget_invalid": 1}
    assert guard.preflight_clr_declarations(b"", **{name: limit + 1})["reason_counts"] == {"preflight_budget_invalid": 1}


def test_byte_downcap_happens_before_header_and_constructor(monkeypatch):
    data = constructor_build_pe()
    assert guard.preflight_clr_declarations(data, max_input_bytes=len(data) - 1)["reason_counts"] == {"preflight_input_byte_budget": 1}
    calls = constructor_factory_counter(monkeypatch, triage)
    result = triage.analyze_managed_pe(data, max_input_bytes=len(data) - 1)
    assert result["status"] == "input_budget_exceeded" and calls == []


@pytest.mark.parametrize("case", ["short", "nt", "optional", "section", "cli", "root", "version",
                                  "stream_count", "stream_overlap", "table_version", "table_short",
                                  "unknown_table", "uncompressed", "unknown_stream", "resource_pair"])
def test_invalid_or_unsupported_raw_is_not_empty_metadata(case, monkeypatch):
    data = constructor_build_pe({6: 1})
    nt, optional, section, metadata, table = 0x80, 0x98, 0x178, 0x300, 0x340
    changes = {
        "nt": (60, (len(data) + 1).to_bytes(4, "little")),
        "optional": (optional, b"\xff\xff"),
        "section": (section + 20, len(data).to_bytes(4, "little")),
        "cli": (optional + 96 + 14 * 8 + 4, (71).to_bytes(4, "little")),
        "root": (metadata, b"NOPE"),
        "version": (metadata + 12, (257).to_bytes(4, "little")),
        "stream_count": (metadata + 30, (65).to_bytes(2, "little")),
        "stream_overlap": (metadata + 44, (1).to_bytes(4, "little")),
        "table_version": (table + 4, b"\x01"),
        "table_short": (metadata + 36, (24).to_bytes(4, "little")),
        "unknown_table": (table + 8, (1 << 63).to_bytes(8, "little")),
        "resource_pair": (0x200 + 24, (0x2000).to_bytes(4, "little")),
    }
    if case == "short":
        data = data[:20]
    elif case == "uncompressed":
        data = constructor_build_pe(table_name=b"#-")
    elif case == "unknown_stream":
        data = constructor_build_pe(table_name=b"#X")
    else:
        data = constructor_insert(data, *changes[case])
    result = guard.preflight_clr_declarations(data)
    assert not result["accepted"], (case, result)
    for module, analyze in ((triage, triage.analyze_managed_pe), (proxy, proxy.analyze_managed_protector)):
        calls = constructor_factory_counter(monkeypatch, module)
        assert analyze(data)["metadata_preflight"]["accepted"] is False
        assert calls == []


def test_raw_guard_budget_does_not_replace_downstream_shared13_budget(monkeypatch):
    from unpackers.tests.resource_literal_pe_fixture import resource_build_literal_pe
    data = resource_build_literal_pe().data
    assert guard.preflight_clr_declarations(data, max_table_rows=2)["reason_counts"] == {
        "preflight_metadata_table_row_budget": 1}
    calls = constructor_factory_counter(monkeypatch, triage, real=True)
    result = triage.analyze_managed_pe(data, max_types=1, max_methods=2)
    assert len(calls) == 1 and result["metadata_preflight"]["accepted"]
    assert result["status"] == "analyzed_partial_budget"
    assert result["reference_metadata_coverage"]["shared_snapshot"]["accepted"] is False


@pytest.mark.parametrize("module_name", ["triage", "proxy"])
@pytest.mark.parametrize("mode", ["missing", "raises"])
def test_failed_guard_dependency_is_fixed_partial_without_constructor(module_name, mode, monkeypatch):
    module = triage if module_name == "triage" else proxy
    analyze = module.analyze_managed_pe if module is triage else module.analyze_managed_protector
    calls = constructor_factory_counter(monkeypatch, module)
    def failed(_data, **_budgets):
        raise RuntimeError("秘密の exception detail")
    monkeypatch.setattr(module, "preflight_clr_declarations", None if mode == "missing" else failed)
    result = analyze(constructor_build_pe())
    assert calls == []
    assert result["metadata_preflight"]["reason_counts"] == {"preflight_dependency_failed": 1}
    assert "秘密" not in json.dumps(result, ensure_ascii=False)



def test_valid_empty_clr_is_explicit_zero_not_rejected_fallback(monkeypatch):
    data = constructor_build_pe()
    result = guard.preflight_clr_declarations(data)
    assert result["accepted"] and result["counts"] == {"tables_declared": 0, "rows_declared": 0}
    for module, analyze in ((triage, triage.analyze_managed_pe), (proxy, proxy.analyze_managed_protector)):
        calls = constructor_factory_counter(monkeypatch, module, real=True)
        result = analyze(data)
        assert len(calls) == 1 and result["metadata_preflight"]["accepted"]
        assert result["resource_coverage"]["inventory_complete"]


@pytest.mark.parametrize("function_name", ["test_analyze_managed_pe_inventory_and_conservative_techniques",
                                           "test_method_reader_receives_bounded_window_for_extra_sections",
                                           "test_lexical_references_preserve_methodspec_field_and_unknown_tokens",
                                           "test_nonempty_typedef_loader_preserves_bound_snapshot"])
def test_original_semantic_assertions_run_on_candidate(function_name, monkeypatch):
    from unpackers.tests import test_managed_il_triage as legacy
    monkeypatch.setattr(legacy, "managed", triage)
    getattr(legacy, function_name)(monkeypatch)


@pytest.mark.parametrize("number", [0, 6, 33, 44])
def test_uint32_max_declaration_has_zero_constructor_calls(number, monkeypatch):
    data = constructor_build_pe({number: 0xffffffff}, payload=False)
    for module, analyze in ((triage, triage.analyze_managed_pe), (proxy, proxy.analyze_managed_protector)):
        calls = constructor_factory_counter(monkeypatch, module)
        result = analyze(data)
        assert calls == []
        assert result["metadata_preflight"]["reason_counts"] == {"preflight_metadata_table_row_budget": 1}


def test_small_valid_declaration_bounds_actual_lazylist_allocation(monkeypatch):
    from dnfile.utils import LazyList
    sizes = []
    original = LazyList.__init__
    def counted(self, evaluator, initial_size):
        sizes.append(initial_size)
        return original(self, evaluator, initial_size)
    monkeypatch.setattr(LazyList, "__init__", counted)
    data = constructor_build_pe({4: 20_000, 6: 20_000})
    assert guard.preflight_clr_declarations(data)["accepted"]
    pe = actual_constructor(data=data, clr_lazy_load=True)
    try:
        assert sorted(sizes) == [20_000, 20_000]
        assert sum(sizes) == 40_000 and max(sizes) <= 20_000
    finally:
        pe.close()


@pytest.mark.parametrize("filename,entry", [("managed_il_triage.py", "analyze_managed_pe"),
                                            ("managed_proxy_deobfuscator.py", "analyze_managed_protector")])
def test_source_order_retains_guard_before_constructor(filename, entry):
    # AST を読むだけで、挿入候補 source や handler を実行する試験ではない。
    tree = ast.parse((ROOT / "unpackers" / filename).read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == entry)
    calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
    guard_calls = [node for node in calls if isinstance(node.func, ast.Name)
                   and node.func.id == "preflight_clr_declarations"]
    constructors = [node for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == "dnPE"]
    assert len(guard_calls) == len(constructors) == 1 and guard_calls[0].lineno < constructors[0].lineno
    reject = [node for node in ast.walk(function) if isinstance(node, ast.If)
              and ast.unparse(node.test) == "not metadata_preflight['accepted']"]
    assert len(reject) == 1 and reject[0].lineno < constructors[0].lineno
    assert any(isinstance(node, ast.Return) for node in reject[0].body)


def test_pure_guard_has_no_runtime_or_io_calls():
    tree = ast.parse((ROOT / "unpackers" / "managed_constructor_guard.py").read_text(encoding="utf-8"))
    names = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert not any(name in {"open", "eval", "exec", "compile", "dnfile.dnPE"}
                   or name.startswith(("subprocess.", "socket.", "requests.")) for name in names)
    assert not any(isinstance(node, ast.Attribute) and node.attr.startswith("__") for node in ast.walk(tree))
    assert {node.name for node in tree.body if isinstance(node, ast.FunctionDef)} == {
        "_integer", "_result", "preflight_clr_declarations"}


@pytest.mark.parametrize("module_name", ["triage", "proxy"])
def test_known_raw_layout_is_not_a_parser_compatibility_or_semantic_promise(module_name, monkeypatch):
    # dnfile0.18 の未実装 AssemblyProcessorRow を raw schema 成功と混同しない。
    module = triage if module_name == "triage" else proxy
    analyze = module.analyze_managed_pe if module is triage else module.analyze_managed_protector
    data = constructor_build_pe({33: 1})
    assert guard.preflight_clr_declarations(data)["accepted"]
    calls = constructor_factory_counter(monkeypatch, module, real=True)
    result = analyze(data)
    assert len(calls) == 1 and result["metadata_preflight"]["accepted"]
    assert result["status"] == ("parse_failed" if module is triage else "parse_error")
    assert result["parse_error"] == "TypeError"
    assert "resource_coverage" not in result
