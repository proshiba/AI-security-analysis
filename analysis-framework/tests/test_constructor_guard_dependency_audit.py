"""constructor guard の固定AST結合を人工sourceだけで確認する。挿入sourceは実行しない。"""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
import sys

import pytest

ROOT = next(path for path in Path(__file__).resolve().parents
            if (path / "unpackers" / "managed_constructor_guard.py").is_file()
            and (path / "analysis-framework" / "common" / "handler_catalog.py").is_file())
COMMON = ROOT / "analysis-framework" / "common"
sys.path.insert(0, str(COMMON))
import handler_catalog as catalog
GUARD = "unpackers/managed_constructor_guard.py"
CALLERS = ("unpackers/managed_il_triage.py", "unpackers/managed_proxy_deobfuscator.py")


@pytest.fixture
def constructor_closure(tmp_path, monkeypatch):
    root = tmp_path / "synthetic_source_closure"
    for relative in (*catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS, *catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS,
                     "unpackers/managed_metadata.py"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    # 人工source closureのpackageはIOなし。通常packageをhandlerとして実行しない。
    (root / "unpackers" / "__init__.py").write_text('"""人工の閉じたsource package。"""\n', encoding="utf-8")
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", root)
    catalog.clear_handler_caches()
    yield root
    catalog.clear_handler_caches()


def constructor_audit(root, relative=GUARD):
    if relative not in (GUARD, *CALLERS):
        relative = "unpackers/managed_resource_snapshot.py"
    entry = ("preflight_clr_declarations" if relative == GUARD else
             "prepare_resource_snapshot" if relative == "unpackers/managed_resource_snapshot.py" else
             catalog._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[relative][0])
    return catalog._recursive_handler_side_effect_audit(root / relative, entry)


def constructor_change(root, relative, source, monkeypatch, *, renew=True):
    path = root / relative
    path.write_text(source, encoding="utf-8")
    if renew:
        mapping = (catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS if relative in catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS
                   else catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS)
        monkeypatch.setitem(mapping, relative, hashlib.sha256(path.read_bytes()).hexdigest())


def constructor_inject(root, relative, function_name, statement, monkeypatch):
    source = (root / relative).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == function_name)
    start = function.body[1] if ast.get_docstring(function) is not None else function.body[0]
    lines = source.splitlines(keepends=True)
    lines.insert(start.lineno - 1, " " * (function.col_offset + 4) + statement + "\n")
    constructor_change(root, relative, "".join(lines), monkeypatch)


def test_constructor_guard_exact_contract_and_all_three_helpers():
    tree = ast.parse((ROOT / GUARD).read_text(encoding="utf-8"))
    assert catalog._managed_constructor_guard_contract(tree)
    assert set(catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS) == {
        GUARD, "unpackers/managed_resources.py", "unpackers/dnfile_resource_adapter.py",
        "unpackers/clr_input_binding.py", "unpackers/managed_resource_snapshot.py"}


@pytest.mark.parametrize("relative", CALLERS)
def test_constructor_consumer_normal_origin_order_and_dispatch(relative):
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    assert catalog._managed_constructor_consumer_contract(tree, relative)
    assert catalog._managed_resource_consumer_contract(tree, relative)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == catalog._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[relative][0])
    call = next(node for node in ast.walk(function) if isinstance(node, ast.Call)
                and catalog._ast_call_name(node.func) == "preflight_clr_declarations")
    assert catalog._managed_resource_consumer_call_shape(call, tree, function, relative,
            "reachable:" + function.name) == ("managed_constructor_guard", "preflight_clr_declarations")


@pytest.mark.parametrize("relative", (GUARD, *CALLERS))
def test_constructor_scope_adds_no_blocker_or_general_consumer_allowance(constructor_closure, relative):
    result = constructor_audit(constructor_closure, relative)
    # 既存consumer全analyzeの非許可能力は、この限定接続で一般許可へ変えない。
    expected = {
        GUARD: [],
        CALLERS[0]: ["reachable:_entropy:unapproved_external_call:collections.Counter",
                     "reachable:_metadata_names:unresolved_higher_order_call:getattr",
                     "reachable:_static_references:unresolved_higher_order_call:getattr",
                     "reachable:_table:unresolved_higher_order_call:getattr",
                     "reachable:analyze_managed_pe:rebound_import_capability:dnfile.dnPE",
                     "reachable:analyze_managed_pe:rebound_import_capability:read_method_body_from_bytes"],
        CALLERS[1]: ["reachable:analyze_managed_protector:rebound_import_capability:dnfile.dnPE",
                     "reachable:analyze_proxy_resources:unapproved_external_call:collections.Counter",
                     "reachable:analyze_proxy_resources:unapproved_object_method:metadata_resolver.coverage",
                     "reachable:resource_summary:unapproved_external_call:collections.Counter"],
    }
    assert result["issues"] == expected[relative], result["issues"]
    assert catalog.MAX_ASSESSMENT_IMPORT_DEPTH == 12
    records = {record["path"] for record in result["files"]}
    assert {GUARD, "unpackers/clr_input_binding.py"} <= records


@pytest.mark.parametrize("function_name", ["_integer", "_result", "preflight_clr_declarations"])
@pytest.mark.parametrize("statement", ['open("synthetic-only", "rb")', '__import__("socket").socket()',
                                      'eval("synthetic-only")', 'data.__class__'])
def test_constructor_new_helper_unsafe_body_is_not_hidden_by_pinrenew(
        constructor_closure, monkeypatch, function_name, statement):
    constructor_inject(constructor_closure, GUARD, function_name, statement, monkeypatch)
    result = constructor_audit(constructor_closure)
    assert result["issues"]
    assert any("forbidden" in issue or "unapproved" in issue or "contract_rejected" in issue for issue in result["issues"])


@pytest.mark.parametrize("relative,name", [
    ("unpackers/clr_input_binding.py", "unique_file_span"),
    ("unpackers/clr_input_binding.py", "canonical_metadata_streams"),
    ("unpackers/clr_input_binding.py", "canonical_table_layout"),
    ("unpackers/clr_input_binding.py", "_row_size"),
])
def test_constructor_binding_callee_body_is_fully_audited(constructor_closure, monkeypatch, relative, name):
    constructor_inject(constructor_closure, relative, name, 'open("synthetic-only", "rb")', monkeypatch)
    result = constructor_audit(constructor_closure)
    assert any("forbidden" in issue or "unapproved" in issue for issue in result["issues"]), result


@pytest.mark.parametrize("mutation", ["large_per", "large_total", "loose_type", "late_type", "late_cap",
                                      "skip_total", "only13", "accept_failure", "foreign_binding",
                                      "rebind_binding", "builtin_shadow", "binding_mutation"])
def test_constructor_guard_downonly_type_and_binding_contract(constructor_closure, monkeypatch, mutation):
    source = (constructor_closure / GUARD).read_text(encoding="utf-8")
    if mutation == "large_per":
        source = source.replace("MAX_TABLE_ROWS = 20_000", "MAX_TABLE_ROWS = 20_001")
    elif mutation == "large_total":
        source = source.replace("MAX_TOTAL_ROWS = 80_000", "MAX_TOTAL_ROWS = 80_001")
    elif mutation == "loose_type":
        source = source.replace("type(data) is not bytes", "not isinstance(data, bytes)")
    elif mutation == "late_type":
        source = source.replace('    if type(data) is not bytes:', '    len(data)\n    if type(data) is not bytes:')
    elif mutation == "late_cap":
        line = "    canonical = binding.canonical_table_layout(data, table_offset, table_size)\n"
        source = source.replace(line, "")
        source = source.replace("    if any(value > max_table_rows for value in declared):", line + "    if any(value > max_table_rows for value in declared):")
    elif mutation == "skip_total":
        source = source.replace("if total > max_total_rows:", "if False:")
    elif mutation == "only13":
        source = source.replace("range(64)", "range(13)")
    elif mutation == "accept_failure":
        source = source.replace('"accepted": not bool(reason)', '"accepted": True')
    elif mutation == "foreign_binding":
        source = source.replace("from . import clr_input_binding", "from foreign import clr_input_binding")
    elif mutation == "rebind_binding":
        source = source.replace("    limits =", "    binding = None\n    limits =", 1)
    elif mutation == "builtin_shadow":
        source += "\ntype = lambda value: bytes\n"
    else:
        source += "\nbinding._SCHEMA[6] = ()\n"
    assert not catalog._managed_constructor_guard_contract(ast.parse(source))
    constructor_change(constructor_closure, GUARD, source, monkeypatch)
    assert "managed_resource_constructor_guard_contract_rejected" in constructor_audit(constructor_closure)["issues"]


def constructor_mutate_caller(source, relative, mutation):
    expression = catalog._MANAGED_CONSTRUCTOR_CALLS[relative]
    if mutation == "foreign_import":
        return source.replace("from .managed_constructor_guard import", "from foreign import")
    if mutation == "namespace_rebind":
        tree = ast.parse(source)
        statement = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                         and isinstance(node.value, ast.Call) and catalog._ast_call_name(node.value.func) == "preflight_clr_declarations")
        lines = source.splitlines(keepends=True)
        lines.insert(statement.lineno - 1, " " * statement.col_offset + "preflight_clr_declarations = None\n")
        return "".join(lines)
    if mutation == "data_rebind":
        return source.replace("    result = {", "    data = bytes()\n    result = {", 1) if relative.endswith("managed_proxy_deobfuscator.py") else source.replace("    budgets = {", "    data = bytes()\n    budgets = {", 1)
    if mutation == "loose_type":
        return source.replace("type(data) is not bytes", "not isinstance(data, bytes)")
    if mutation == "type_shadow":
        return source + "\ntype = lambda value: bytes\n"
    if mutation == "late_guard":
        source = source.replace('    result["metadata_preflight"] = metadata_preflight', '    pe = dnfile.dnPE(data=data, clr_lazy_load=True)\n    result["metadata_preflight"] = metadata_preflight', 1)
        return source
    if mutation == "fallback_success":
        return source.replace('"status": "partial", "accepted": False,\n                              "scope": "constructor_declarations_only"', '"status": "partial", "accepted": True,\n                              "scope": "constructor_declarations_only"')
    if mutation == "invert_reject":
        return source.replace('if not metadata_preflight["accepted"]:', 'if metadata_preflight["accepted"]:')
    if mutation == "nested_return":
        tree = ast.parse(source)
        reject = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "not metadata_preflight['accepted']")
        statement = reject.body[-1]
        assert isinstance(statement, ast.Return)
        lines = source.splitlines(keepends=True)
        lines[statement.lineno - 1] = " " * statement.col_offset + "if False:\n" + " " * (statement.col_offset + 4) + "return result\n"
        return "".join(lines)
    if mutation == "result_mutation":
        return source.replace('    result["metadata_preflight"] = metadata_preflight', '    metadata_preflight["accepted"] = True\n    result["metadata_preflight"] = metadata_preflight', 1)
    if mutation == "nested_guard":
        tree = ast.parse(source)
        statement = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                         and isinstance(node.value, ast.Call) and catalog._ast_call_name(node.value.func) == "preflight_clr_declarations")
        lines = source.splitlines(keepends=True)
        body = lines[statement.lineno - 1:statement.end_lineno]
        lines[statement.lineno - 1:statement.end_lineno] = [" " * statement.col_offset + "if False:\n"] + ["    " + line for line in body]
        return "".join(lines)
    if mutation == "foreign_factory":
        return source.replace("pe = dnfile.dnPE(data=data, clr_lazy_load=True)", "pe = foreign_factory(data)", 1)
    if mutation == "shared_before_constructor":
        tree = ast.parse(source)
        entry = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == catalog._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[relative][0])
        assignment = next(node for node in ast.walk(entry) if isinstance(node, ast.Assign)
                          and isinstance(node.value, ast.Call) and catalog._ast_call_name(node.value.func) == "prepare_resource_snapshot")
        lines = source.splitlines(keepends=True)
        statement = "".join(lines[assignment.lineno - 1:assignment.end_lineno])
        del lines[assignment.lineno - 1:assignment.end_lineno]
        marker = next(index for index, line in enumerate(lines) if "pe = dnfile.dnPE(" in line)
        lines.insert(marker, statement)
        return "".join(lines)
    if mutation == "other_scope":
        return source + "\ndef _synthetic_foreign(data):\n    return preflight_clr_declarations(data)\n"
    if mutation == "aliased_import":
        return source.replace("import preflight_clr_declarations", "import preflight_clr_declarations as other")
    raise AssertionError(mutation)


@pytest.mark.parametrize("relative", CALLERS)
@pytest.mark.parametrize("mutation", ["foreign_import", "namespace_rebind", "data_rebind", "loose_type",
                                      "type_shadow", "late_guard", "fallback_success", "invert_reject",
                                      "nested_return", "result_mutation", "nested_guard", "foreign_factory",
                                      "shared_before_constructor", "other_scope", "aliased_import"])
def test_constructor_caller_order_and_origin_fixed_even_after_pinrenew(constructor_closure, monkeypatch, relative, mutation):
    source = (constructor_closure / relative).read_text(encoding="utf-8")
    changed = constructor_mutate_caller(source, relative, mutation)
    assert changed != source
    tree = ast.parse(changed)
    assert not catalog._managed_resource_consumer_contract(tree, relative)
    constructor_change(constructor_closure, relative, changed, monkeypatch)
    result = constructor_audit(constructor_closure, relative)
    assert any("managed_resource_consumer_origin_or_commitment_rejected" in issue for issue in result["issues"]), result


@pytest.mark.parametrize("relative", (GUARD, *CALLERS))
def test_constructor_same_length_change_needs_current_source_commitment(constructor_closure, monkeypatch, relative):
    source = (constructor_closure / relative).read_text(encoding="utf-8")
    assert "constructor" in source
    changed = source.replace("constructor", "constructoz", 1)
    assert len(changed) == len(source)
    constructor_change(constructor_closure, relative, changed, monkeypatch, renew=False)
    result = constructor_audit(constructor_closure, relative)
    assert any("commitment" in issue for issue in result["issues"]), result


@pytest.mark.parametrize("relative", list(catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS))
@pytest.mark.parametrize("kind", ["async", "duplicate", "unused_sink"])
def test_constructor_five_closed_modules_keep_async_duplicate_and_allbody_rejection(
        constructor_closure, monkeypatch, relative, kind):
    source = (constructor_closure / relative).read_text(encoding="utf-8")
    if kind == "async":
        source += "\nasync def _synthetic_unreachable():\n    return None\n"
        expected = "managed_resource_async_function_unsupported:" + relative
    elif kind == "duplicate":
        name = next(node.name for node in ast.parse(source).body if isinstance(node, ast.FunctionDef))
        source += "\ndef " + name + "(*args):\n    return None\n"
        expected = "managed_resource_duplicate_function_name:" + relative
    else:
        source += '\ndef _synthetic_unreachable():\n    open("synthetic-only", "rb")\n'
        expected = None
    constructor_change(constructor_closure, relative, source, monkeypatch)
    result = constructor_audit(constructor_closure, relative)
    assert expected in result["issues"] if expected else any("forbidden" in issue or "unapproved" in issue for issue in result["issues"])


def test_constructor_foreign_caller_cannot_use_new_helper(constructor_closure, monkeypatch):
    source = constructor_closure / "foreign.py"
    source.write_text("from unpackers.managed_constructor_guard import preflight_clr_declarations\ndef entry(data):\n    return preflight_clr_declarations(data)\n", encoding="utf-8")
    result = catalog._recursive_handler_side_effect_audit(source, "entry")
    assert any("managed_resource_unreviewed_caller" in issue for issue in result["issues"]), result


def test_constructor_real_import_depth_stays_twelve(tmp_path, monkeypatch):
    for number in range(14):
        suffix = "import m" + str(number + 1) + "\n" if number < 13 else ""
        (tmp_path / ("m" + str(number) + ".py")).write_text(suffix + "def entry():\n    return None\n", encoding="utf-8")
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", tmp_path)
    result = catalog._recursive_handler_side_effect_audit(tmp_path / "m0.py", "entry")
    assert catalog.MAX_ASSESSMENT_IMPORT_DEPTH == 12 and "import_depth_limit:m13.py" in result["issues"]

@pytest.mark.parametrize("relative", CALLERS)
@pytest.mark.parametrize("kind", ["safe_then_unsafe", "unsafe_then_safe", "safe_then_async", "pure_then_unsafe"])
def test_constructor_entry_identity_includes_sync_and_async_duplicates(constructor_closure, monkeypatch, relative, kind):
    source = (constructor_closure / relative).read_text(encoding="utf-8")
    entry = catalog._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[relative][0]
    prefix = "async " if kind == "safe_then_async" else ""
    duplicate = "\n" + prefix + "def " + entry + "(data):\n    open('synthetic-only', 'rb')\n"
    if kind == "pure_then_unsafe":
        tree = ast.parse(source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == entry)
        lines = source.splitlines(keepends=True)
        lines[function.lineno - 1:function.end_lineno] = ["def " + entry + "(data):\n    return None\n" + duplicate]
        changed = "".join(lines)
    elif kind == "unsafe_then_safe":
        tree = ast.parse(source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == entry)
        lines = source.splitlines(keepends=True)
        lines.insert(function.lineno - 1, duplicate)
        changed = "".join(lines)
    else:
        changed = source + duplicate
    assert not catalog._managed_constructor_consumer_contract(ast.parse(changed), relative)
    constructor_change(constructor_closure, relative, changed, monkeypatch)
    result = constructor_audit(constructor_closure, relative)
    assert any("managed_resource_consumer_origin_or_commitment_rejected" in issue for issue in result["issues"])

def test_constructor_enumerate_builtin_cannot_be_rebound(constructor_closure, monkeypatch):
    source = (constructor_closure / GUARD).read_text(encoding="utf-8") + "\nenumerate = lambda value: ()\n"
    assert not catalog._managed_constructor_guard_contract(ast.parse(source))
    constructor_change(constructor_closure, GUARD, source, monkeypatch)
    assert "managed_resource_constructor_guard_contract_rejected" in constructor_audit(constructor_closure)["issues"]
