"""新resource factoryの依存bodyを実行せず、固定AST到達監査だけで点検する。"""

import ast
import hashlib
from pathlib import Path
import sys

import pytest

ROOT = next(parent for parent in Path(__file__).resolve().parents
            if (parent / "unpackers" / "managed_resource_snapshot.py").is_file()
            and (parent / "analysis-framework").is_dir())
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import handler_catalog as catalog


def test_new_factory_fixed_closure_is_audited():
    result = catalog._recursive_handler_side_effect_audit(
        ROOT / "unpackers" / "managed_resource_snapshot.py", "prepare_resource_snapshot")
    assert result["issues"] == [], result["issues"]
    assert result["allowance_counts"]["reviewed_managed_resource_fixed_allocator"] == 1


@pytest.fixture
def copied_closure(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    for relative in (*catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS, *catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS,
                     "unpackers/managed_metadata.py", "unpackers/__init__.py"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", root)
    catalog.clear_handler_caches()
    yield root
    catalog.clear_handler_caches()


def _audit(root, relative=None):
    # constructor guardはfactoryの依存ではないため、対象の入口から到達監査する。
    if relative == "unpackers/managed_constructor_guard.py":
        return catalog._recursive_handler_side_effect_audit(root / relative, "preflight_clr_declarations")
    return catalog._recursive_handler_side_effect_audit(root / "unpackers/managed_resource_snapshot.py", "prepare_resource_snapshot")


def _change(root, relative, source, monkeypatch, *, renew=True):
    path = root / relative
    path.write_text(source, encoding="utf-8")
    if renew:
        mapping = (catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS if relative in catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS
                   else catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS if relative in catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS
                   else catalog._MANAGED_READER_SOURCE_COMMITMENTS)
        monkeypatch.setitem(mapping, relative, hashlib.sha256(path.read_bytes()).hexdigest())


def _inject(root, relative, name, statement, monkeypatch):
    source = (root / relative).read_text(encoding="utf-8")
    tree = ast.parse(source)
    if "." in name:
        class_name, method_name = name.split(".")
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
        function = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == method_name)
    else:
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)
    start = function.body[1] if isinstance(function.body[0], ast.Expr) and isinstance(function.body[0].value, ast.Constant) and isinstance(function.body[0].value.value, str) else function.body[0]
    lines = source.splitlines(keepends=True)
    lines.insert(start.lineno - 1, " " * (function.col_offset + 4) + statement + "\n")
    _change(root, relative, "".join(lines), monkeypatch)


@pytest.mark.parametrize("capability", [
    'open("synthetic-only", "rb")', '__import__("socket").socket()',
    '__import__("subprocess").run(["synthetic-only"])',
    '__import__("clr").AddReference("synthetic-only")', 'eval("synthetic-only")',
])
@pytest.mark.parametrize("relative,name", [
    ("unpackers/managed_resource_snapshot.py", "shared_metadata_state"),
    ("unpackers/managed_resources.py", "coverage"),
    ("unpackers/dnfile_resource_adapter.py", "materialize_lazy_row"),
    ("unpackers/clr_input_binding.py", "canonical_metadata_streams"),
    ("unpackers/managed_metadata.py", "MetadataResolver.__init__"),
])
def test_source_renewal_does_not_skip_callee_capability_audit(copied_closure, monkeypatch, capability, relative, name):
    _inject(copied_closure, relative, name, capability, monkeypatch)
    result = _audit(copied_closure)
    assert result["issues"], (relative, name, capability)
    assert any("forbidden" in issue or "unapproved" in issue or "unresolved" in issue for issue in result["issues"])


@pytest.mark.parametrize("kind", ["unused_helper", "indirect_helper", "self_method"])
def test_all_helpers_and_internal_self_methods_are_audited(copied_closure, monkeypatch, kind):
    relative = "unpackers/managed_resources.py"
    source = (copied_closure / relative).read_text(encoding="utf-8")
    if kind in {"unused_helper", "indirect_helper"}:
        source += '\ndef _synthetic_unsafe():\n    open("synthetic-only", "rb")\n'
        _change(copied_closure, relative, source, monkeypatch)
        if kind == "indirect_helper":
            _inject(copied_closure, relative, "_snapshot_rows", "_synthetic_unsafe()", monkeypatch)
    else:
        source = source.replace('    def coverage(self) -> dict[str, Any]:',
            '    def _synthetic_unsafe(self):\n        open("synthetic-only", "rb")\n\n    def coverage(self) -> dict[str, Any]:', 1)
        _change(copied_closure, relative, source, monkeypatch)
        _inject(copied_closure, relative, "coverage", "self._synthetic_unsafe()", monkeypatch)
    assert _audit(copied_closure)["issues"]


@pytest.mark.parametrize("mutation", ["wrong_class", "class_allocator", "wrong_scope", "foreign_import", "builtin_shadow", "parameter_rebind"])
def test_allocator_and_origin_are_closed_to_the_fixed_ast(copied_closure, monkeypatch, mutation):
    relative = "unpackers/managed_resource_snapshot.py"
    source = (copied_closure / relative).read_text(encoding="utf-8")
    if mutation == "wrong_class":
        source = source.replace("object.__new__(MetadataResolver)", "object.__new__(object)")
    elif mutation == "class_allocator":
        source = source.replace("object.__new__(MetadataResolver)", "MetadataResolver.__new__(MetadataResolver)")
    elif mutation == "wrong_scope":
        source += '\ndef _synthetic_wrong_allocator():\n    return object.__new__(MetadataResolver)\n'
    elif mutation == "foreign_import":
        source = source.replace("from .managed_metadata import", "from untrusted import")
    elif mutation == "builtin_shadow":
        source = source.replace("    resolver = object.__new__(MetadataResolver)", "    object = MetadataResolver\n    resolver = object.__new__(MetadataResolver)")
    else:
        source = source.replace("    resolver = object.__new__(MetadataResolver)", "    pe = None\n    resolver = object.__new__(MetadataResolver)")
    _change(copied_closure, relative, source, monkeypatch)
    assert _audit(copied_closure)["issues"]


@pytest.mark.parametrize("relative", list(catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS))
def test_each_new_source_requires_its_own_commitment(copied_closure, monkeypatch, relative):
    source = (copied_closure / relative).read_text(encoding="utf-8") + "\n# 未レビュー版\n"
    _change(copied_closure, relative, source, monkeypatch, renew=False)
    assert any("managed_resource_source_commitment_mismatch" in issue for issue in _audit(copied_closure, relative)["issues"])


@pytest.mark.parametrize("relative", list(catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS))
def test_normal_consumer_has_exact_dnpe_tuple_and_caller_contract(relative):
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    assert catalog._managed_resource_consumer_contract(tree, relative)
    matched = []
    for scope in (node for node in tree.body if isinstance(node, ast.FunctionDef)):
        for call in (node for node in catalog._nodes_in_lexical_scope(scope) if isinstance(node, ast.Call)):
            result = catalog._managed_resource_consumer_call_shape(call, tree, scope, relative, f"reachable:{scope.name}")
            if result is not None:
                matched.append(result)
    assert ("managed_resource_snapshot", "prepare_resource_snapshot") in matched
    assert ("managed_resource_snapshot", "revalidated_resource_scan") in matched
    assert ("managed_resources", "coverage") in matched
    assert ("managed_metadata", "coverage") in matched


@pytest.mark.parametrize("relative", list(catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS))
@pytest.mark.parametrize("mutation", ["lazy_false", "foreign_pe", "tuple_order", "extra_receiver", "namespace_rebind",
                                     "namespace_mutation", "extra_fallback", "data_rebind", "extra_caller", "foreign_wrapper_argument",
                                     "receiver_attribute", "receiver_item"])
def test_consumer_contract_rejects_origin_and_rebinding_without_execution(relative, mutation):
    source = (ROOT / relative).read_text(encoding="utf-8")
    entry, scope_name, wrapper, *_ = catalog._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[relative]
    if mutation == "lazy_false":
        source = source.replace("clr_lazy_load=True", "clr_lazy_load=False")
    elif mutation == "foreign_pe":
        source = source.replace("pe = dnfile.dnPE(data=data, clr_lazy_load=True)", "pe = foreign(data)")
    elif mutation == "tuple_order":
        source = source.replace("resource_scan, resolver, shared_work = prepare_resource_snapshot(", "resolver, resource_scan, shared_work = prepare_resource_snapshot(")
    elif mutation == "extra_receiver":
        source = source.replace("    fresh = revalidated_resource_scan(data, resource_scan)", "    resource_scan = None\n    fresh = revalidated_resource_scan(data, resource_scan)")
    elif mutation == "namespace_rebind":
        source += "\nprepare_resource_snapshot = None\n"
    elif mutation == "namespace_mutation":
        source += "\ndnfile.dnPE = None\n"
    elif mutation == "extra_fallback":
        source += "\ndnfile = None\n"
    elif mutation == "data_rebind":
        source = source.replace("    fresh = revalidated_resource_scan(data, resource_scan)", "    data = b''\n    fresh = revalidated_resource_scan(data, resource_scan)")
    elif mutation == "extra_caller":
        source += f"\ndef _synthetic_extra(data, pe):\n    return {scope_name}(data, pe)\n"
    elif mutation == "receiver_attribute":
        source = source.replace("    coverage = resolver.coverage()", "    scan._coverage = {}\n    coverage = resolver.coverage()")
    elif mutation == "receiver_item":
        source = source.replace("    coverage = resolver.coverage()", "    work['accepted'] = True\n    coverage = resolver.coverage()")
    else:
        source = source.replace(f"{scope_name}(data, pe)", f"{scope_name}(data, foreign_pe)") if relative.endswith("managed_proxy_deobfuscator.py") else source.replace(
            "_resource_inventory_scope(data, pe, max_resources, max_resource_bytes)",
            "_resource_inventory_scope(data, foreign_pe, max_resources, max_resource_bytes)")
    assert not catalog._managed_resource_consumer_contract(ast.parse(source), relative), mutation


@pytest.mark.parametrize("relative", list(catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS))
@pytest.mark.parametrize("mutation", ["tuple_order", "foreign_pe", "receiver_attribute", "namespace_rebind"])
def test_renewed_consumer_pin_still_requires_exact_origin(copied_closure, monkeypatch, relative, mutation):
    source = (copied_closure / relative).read_text(encoding="utf-8")
    if mutation == "tuple_order":
        source = source.replace("resource_scan, resolver, shared_work = prepare_resource_snapshot(", "resolver, resource_scan, shared_work = prepare_resource_snapshot(")
    elif mutation == "foreign_pe":
        source = source.replace("pe = dnfile.dnPE(data=data, clr_lazy_load=True)", "pe = foreign(data)")
    elif mutation == "receiver_attribute":
        source = source.replace("    coverage = resolver.coverage()", "    scan._coverage = {}\n    coverage = resolver.coverage()")
    else:
        source += "\nprepare_resource_snapshot = None\n"
    _change(copied_closure, relative, source, monkeypatch)
    entry = catalog._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[relative][0]
    result = catalog._recursive_handler_side_effect_audit(copied_closure / relative, entry)
    assert any("managed_resource_consumer_origin_or_commitment_rejected" in issue for issue in result["issues"]), result


@pytest.mark.parametrize("statement", [
    "from unpackers.managed_resource_snapshot import prepare_resource_snapshot\ndef extract(data):\n    return prepare_resource_snapshot(data, None)\n",
    "import unpackers.managed_resource_snapshot as resource\ndef extract(data):\n    return resource.prepare_resource_snapshot(data, None)\n",
    "from unpackers import managed_resource_snapshot as resource\ndef extract(data):\n    return resource.prepare_resource_snapshot(data, None)\n",
    "from unpackers.managed_resources import describe_clr_resources\ndef extract(data):\n    return describe_clr_resources(data, None)\n",
    "from unpackers.dnfile_resource_adapter import materialize_lazy_row\ndef extract(data):\n    return materialize_lazy_row(data, None, None, None, None, 0, 1)\n",
])
def test_unknown_caller_is_not_a_global_safe_entry(copied_closure, statement):
    path = copied_closure / "extractors" / "synthetic" / "extractor.py"
    path.parent.mkdir(parents=True)
    path.write_text(statement, encoding="utf-8")
    result = catalog._recursive_handler_side_effect_audit(path, "extract")
    assert any("managed_resource_unreviewed_caller" in issue for issue in result["issues"]), result


@pytest.mark.parametrize("symbol", ["_resource_inventory", "_resource_inventory_scope", "_consumed_metadata_coverage"])
def test_parser_view_compatibility_wrapper_is_not_a_handler_safe_entry(copied_closure, symbol):
    path = copied_closure / "extractors" / "synthetic" / "extractor.py"
    path.parent.mkdir(parents=True)
    path.write_text(f"from unpackers.managed_il_triage import {symbol}\ndef extract(data):\n    return {symbol}(data, None)\n", encoding="utf-8")
    result = catalog._recursive_handler_side_effect_audit(path, "extract")
    assert any("managed_resource_unreviewed_consumer_helper" in issue for issue in result["issues"]), result


@pytest.mark.parametrize("relative", list(catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS))
def test_reachable_consumer_resource_closure_preserves_existing_guard_failures(relative):
    entry = catalog._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[relative][0]
    result = catalog._recursive_handler_side_effect_audit(ROOT / relative, entry)
    expected = {
        "unpackers/managed_il_triage.py": {
            "reachable:_entropy:unapproved_external_call:collections.Counter",
            "reachable:_metadata_names:unresolved_higher_order_call:getattr",
            "reachable:_static_references:unresolved_higher_order_call:getattr",
            "reachable:_table:unresolved_higher_order_call:getattr",
            "reachable:analyze_managed_pe:rebound_import_capability:dnfile.dnPE",
            "reachable:analyze_managed_pe:rebound_import_capability:read_method_body_from_bytes",
        },
        "unpackers/managed_proxy_deobfuscator.py": {
            "reachable:analyze_managed_protector:rebound_import_capability:dnfile.dnPE",
            "reachable:analyze_proxy_resources:unapproved_external_call:collections.Counter",
            "reachable:analyze_proxy_resources:unapproved_object_method:metadata_resolver.coverage",
            "reachable:resource_summary:unapproved_external_call:collections.Counter",
        },
    }
    assert set(result["issues"]) == expected[relative]
    assert not any("managed_resource" in issue for issue in result["issues"]), result
    assert result["allowance_counts"].get("reviewed_managed_resource_consumer_source_call", 0) >= 5


@pytest.mark.parametrize("handler_id", [
    "asyncrat:extractors.asyncrat.extractor.py:extract",
    "donutloader:extractors.donutloader.extractor.py:extract",
    "purehvnc:analysis.framework.malware.purehvnc.extract.config.py:extract_config",
    "purehvnc:extractors.purehvnc.extractor.py:extract",
])
def test_existing_managed_detector_preflight_remains_static_only(monkeypatch, handler_id):
    # 通常repositoryのsourceだけを読み、handler本体や検体は実行しない。
    for name, value in {
        "REPOSITORY_ROOT": ROOT, "FRAMEWORK_ROOT": ROOT / "analysis-framework",
        "MALWARE_ROOT": ROOT / "analysis-framework" / "malware",
        "EXTRACTORS_ROOT": ROOT / "extractors",
        "PROFILE_PATH": ROOT / "extractors" / "profiles" / "windows_family_profiles.json",
    }.items():
        monkeypatch.setattr(catalog, name, value)
    catalog.clear_handler_caches()
    try:
        specs = {spec.id: spec for spec in catalog.discover_handlers()}
        result = catalog.preflight_handler_for_assessment(specs[handler_id], actual_format="pe", input_size=1)
        assert result["eligible"] is True, result["blockers"]
        assert result["blockers"] == []
        assert result["sample_execution_allowed"] is False
        assert result["network_allowed"] is False
        assert result["filesystem_write_allowed"] is False
    finally:
        catalog.clear_handler_caches()


@pytest.mark.parametrize("relative", list(catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS))
@pytest.mark.parametrize("shape", ["unsafe_then_safe", "safe_then_safe", "async_unsafe_then_safe", "safe_then_async_safe"])
def test_duplicate_module_function_names_are_rejected_after_pin_renewal(copied_closure, monkeypatch, relative, shape):
    source = (copied_closure / relative).read_text(encoding="utf-8")
    first_prefix = "async def" if shape == "async_unsafe_then_safe" else "def"
    second_prefix = "async def" if shape == "safe_then_async_safe" else "def"
    first_body = 'open("synthetic-only", "rb")' if shape in {"unsafe_then_safe", "async_unsafe_then_safe"} else "return None"
    source += f"\n{first_prefix} _resource_synthetic_duplicate():\n    {first_body}\n\n{second_prefix} _resource_synthetic_duplicate():\n    return None\n"
    _change(copied_closure, relative, source, monkeypatch)
    result = _audit(copied_closure, relative)
    assert f"managed_resource_duplicate_function_name:{relative}" in result["issues"]


@pytest.mark.parametrize("relative,class_name", [
    ("unpackers/managed_resources.py", "_RowSnapshot"),
    ("unpackers/managed_resources.py", "_ResourceDescriptor"),
    ("unpackers/managed_resources.py", "_ResourceScan"),
    ("unpackers/dnfile_resource_adapter.py", "_HeapBinding"),
])
@pytest.mark.parametrize("shape", ["unsafe_then_safe", "safe_then_safe", "async_unsafe_then_safe", "safe_then_async_safe"])
def test_duplicate_class_method_names_are_rejected_after_pin_renewal(copied_closure, monkeypatch, relative, class_name, shape):
    source = (copied_closure / relative).read_text(encoding="utf-8")
    owner = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == class_name)
    first_prefix = "async def" if shape == "async_unsafe_then_safe" else "def"
    second_prefix = "async def" if shape == "safe_then_async_safe" else "def"
    first_body = 'open("synthetic-only", "rb")' if "unsafe" in shape else "return None"
    addition = (f"\n    {first_prefix} _resource_synthetic_duplicate(self):\n        {first_body}\n"
                f"\n    {second_prefix} _resource_synthetic_duplicate(self):\n        return None\n")
    lines = source.splitlines(keepends=True)
    lines.insert(owner.end_lineno, addition)
    _change(copied_closure, relative, "".join(lines), monkeypatch, renew=True)
    result = _audit(copied_closure)
    assert f"managed_resource_duplicate_method_name:{relative}:{class_name}" in result["issues"]



@pytest.mark.parametrize("relative", list(catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS))
def test_unique_async_module_function_is_unsupported_after_pin_renewal(copied_closure, monkeypatch, relative):
    source = (copied_closure / relative).read_text(encoding="utf-8")
    source += '\nasync def _resource_synthetic_unique_async():\n    open("synthetic-only", "rb")\n'
    _change(copied_closure, relative, source, monkeypatch, renew=True)
    result = _audit(copied_closure, relative)
    assert f"managed_resource_async_function_unsupported:{relative}" in result["issues"]


@pytest.mark.parametrize("relative,class_name", [
    ("unpackers/managed_resources.py", "_RowSnapshot"),
    ("unpackers/managed_resources.py", "_ResourceDescriptor"),
    ("unpackers/managed_resources.py", "_ResourceScan"),
    ("unpackers/dnfile_resource_adapter.py", "_HeapBinding"),
])
def test_unique_async_class_method_is_unsupported_after_pin_renewal(copied_closure, monkeypatch, relative, class_name):
    source = (copied_closure / relative).read_text(encoding="utf-8")
    owner = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == class_name)
    lines = source.splitlines(keepends=True)
    lines.insert(owner.end_lineno, '\n    async def _resource_synthetic_unique_async(self):\n        open("synthetic-only", "rb")\n')
    _change(copied_closure, relative, "".join(lines), monkeypatch, renew=True)
    result = _audit(copied_closure)
    assert f"managed_resource_async_method_unsupported:{relative}:{class_name}" in result["issues"]
