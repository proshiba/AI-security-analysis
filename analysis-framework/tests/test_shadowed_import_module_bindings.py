"""人工ASTでmanifest補完の同一source条件とfail-closedを確認する。"""

from __future__ import annotations

import ast
from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
import handler_catalog as catalog


def _synthetic(monkeypatch, source_text, *, audited=True, extra=None, audit_extra=False):
    root = Path(r"C:\synthetic-module-bindings")
    source, package, helper = root / "consumer.py", root / "__init__.py", root / "helper.py"
    mapping = {"pkg": package, "pkg.consumer": source, "helper": helper, "pkg.helper": helper}
    if extra:
        mapping.update(extra)
    monkeypatch.setattr(catalog, "_resolve_local_module_path", lambda _source, name: (mapping.get(name), None))
    monkeypatch.setattr(catalog, "_approved_external_module", lambda name: name == "typing")
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    bindings = {"pkg": (package, True), "pkg.consumer": (source, False), "helper": (helper, False)}
    files = {source: "a", package: "b"}
    if audited:
        files[helper] = "c"
    if extra and audit_extra:
        for target in extra.values():
            files[target] = "d"
    trees = {source: ast.parse(source_text), package: ast.parse(""), helper: ast.parse("")}
    for target in files:
        trees.setdefault(target, ast.parse(""))
    issues = set()
    catalog._complete_shadowed_import_module_bindings(bindings, trees, files, frozenset(files), issues)
    return bindings, issues


def test_relative_and_bare_same_source_preserve_both_names(monkeypatch):
    bindings, issues = _synthetic(monkeypatch, "try:\n from .helper import value\nexcept ImportError:\n from helper import value\n")
    assert issues == set()
    assert bindings["pkg.helper"] == bindings["helper"]


@pytest.mark.parametrize("primary,fallback", [("value", "other"), ("value", "value as other")])
def test_different_same_alias_symbol_is_rejected(monkeypatch, primary, fallback):
    text = "try:\n from .helper import " + primary + " as shared\nexcept ImportError:\n from helper import " + fallback + " as shared\n"
    if " as other" in fallback:
        text = "from .helper import value as shared\nfrom helper import other as shared\n"
    _bindings, issues = _synthetic(monkeypatch, text)
    assert any(item.startswith("shadowed_import_alias_target_conflict:") for item in issues)


def test_alternative_source_is_not_added_when_unaudited(monkeypatch):
    bindings, issues = _synthetic(monkeypatch, "from .helper import value\nfrom helper import value\n", audited=False)
    assert "pkg.helper" not in bindings
    assert any(item.startswith("shadowed_import_source_not_audited:") for item in issues)


def test_unknown_alternative_import_rejects(monkeypatch):
    _bindings, issues = _synthetic(monkeypatch, "try:\n from unknown import value\nexcept ImportError:\n from helper import value\n")
    assert "shadowed_import_unresolved:unknown" in issues


def test_same_source_two_distinct_aliases_are_preserved(monkeypatch):
    bindings, issues = _synthetic(monkeypatch, "from .helper import value as one, other as two\nfrom helper import value as one, other as two\n")
    assert not issues
    assert bindings["pkg.helper"] == bindings["helper"]


def test_relative_context_without_fallback_rejects(monkeypatch):
    _bindings, issues = _synthetic(monkeypatch, "from ...helper import value\n")
    assert any(item.startswith("shadowed_import_context_unavailable:") for item in issues)


def test_same_alias_different_audited_source_is_rejected(monkeypatch):
    other = Path(r"C:\synthetic-module-bindings\other.py")
    bindings, issues = _synthetic(monkeypatch, "from .helper import value as shared\nfrom other import value as shared\n", extra={"other": other}, audit_extra=True)
    assert "pkg.helper" not in bindings
    assert any(item.startswith("shadowed_import_alias_target_conflict:") for item in issues)


def test_duplicate_imports_in_one_statement_are_not_hidden(monkeypatch):
    other = Path(r"C:\synthetic-module-bindings\other.py")
    _bindings, issues = _synthetic(monkeypatch, "import helper as shared, other as shared\n", extra={"other": other}, audit_extra=True)
    assert any(item.startswith("shadowed_import_alias_target_conflict:") for item in issues)


def test_unknown_unreachable_function_does_not_expand_import_manifest(monkeypatch):
    bindings, issues = _synthetic(monkeypatch, "from helper import value\ndef not_reached():\n import unknown\n")
    assert not issues
    assert "unknown" not in bindings


def test_star_import_is_not_guessed(monkeypatch):
    _bindings, issues = _synthetic(monkeypatch, "from helper import *\n")
    assert any(item.startswith("shadowed_import_star_not_supported:") for item in issues)


def test_binding_count_limit_is_not_relaxed(monkeypatch):
    monkeypatch.setattr(catalog, "MAX_ASSESSMENT_IMPORT_FILES", 1)
    _bindings, issues = _synthetic(monkeypatch, "from .helper import value\nfrom helper import value\nfrom helper import other\n")
    assert not issues
    monkeypatch.setattr(catalog, "MAX_ASSESSMENT_IMPORT_FILES", 0)
    _bindings, issues = _synthetic(monkeypatch, "from .helper import value\nfrom helper import value\n")
    assert "import_module_binding_limit" in issues


@pytest.mark.parametrize("body", ["import sys\nsys.path.insert(0, 'unexpected')\ndef extract(data):\n return {}", "import sys\nsys.modules['unexpected'] = None\ndef extract(data):\n return {}", "import socket\ndef extract(data):\n socket.socket()"])
def test_existing_side_effect_guards_still_reject_unsafe_source_ast(tmp_path, monkeypatch, body):
    source = tmp_path / "ordinary_source.py"
    source.write_text(body + "\n", encoding="utf-8")
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", tmp_path)
    audit = catalog._recursive_handler_side_effect_audit(source, "extract")
    assert audit["issues"]


def test_unaliased_external_siblings_bind_same_parent(monkeypatch):
    source = Path(r"C:\synthetic-independent\consumer.py")
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    monkeypatch.setattr(catalog, "_resolve_local_module_path", lambda _source, _name: (None, None))
    bindings = {"consumer": (source, False)}
    trees = {source: ast.parse("import importlib.util\nimport importlib.machinery\n")}
    issues = set()
    catalog._complete_shadowed_import_module_bindings(bindings, trees, {source: "a"}, frozenset({source}), issues)
    assert not issues, issues


def test_unaliased_local_siblings_bind_same_parent(monkeypatch):
    root = Path(r"C:\synthetic-independent")
    source, package, first, second = root / "consumer.py", root / "__init__.py", root / "a.py", root / "b.py"
    targets = {"pkg": package, "pkg.a": first, "pkg.b": second}
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    monkeypatch.setattr(catalog, "_resolve_local_module_path", lambda _source, name: (targets.get(name), None))
    bindings = {"consumer": (source, False), "pkg": (package, True), "pkg.b": (second, False)}
    trees = {source: ast.parse("import pkg.a\nimport pkg.b\n"), package: ast.parse(""), first: ast.parse(""), second: ast.parse("")}
    files = {source: "a", package: "b", first: "c", second: "d"}
    issues = set()
    catalog._complete_shadowed_import_module_bindings(bindings, trees, files, frozenset(files), issues)
    assert not issues, issues
    assert bindings["pkg.a"] == (first, False)


def _local_setup(monkeypatch, source_text, *, second_audited=True):
    root = Path(r"C:\synthetic-root-binding-boundary")
    source, package, first, second = root / "consumer.py", root / "__init__.py", root / "a.py", root / "b.py"
    targets = {"pkg": package, "pkg.a": first, "pkg.b": second}
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    monkeypatch.setattr(catalog, "_resolve_local_module_path", lambda _source, name: (targets.get(name), None))
    bindings = {"consumer": (source, False), "pkg": (package, True)}
    trees = {source: ast.parse(source_text), package: ast.parse(""), first: ast.parse(""), second: ast.parse("")}
    files = {source: "a", package: "b", first: "c"}
    if second_audited:
        files[second] = "d"
    issues = set()
    catalog._complete_shadowed_import_module_bindings(bindings, trees, files, frozenset(files), issues)
    return bindings, issues


def test_same_root_unreviewed_local_child_is_not_permitted(monkeypatch):
    bindings, issues = _local_setup(monkeypatch, "import pkg.a\nimport pkg.b\n", second_audited=False)
    assert "shadowed_import_source_not_audited:pkg.b" in issues
    assert "pkg.b" not in bindings


def test_same_root_full_module_alias_still_conflicts(monkeypatch):
    bindings, issues = _local_setup(monkeypatch, "import pkg.a as shared\nimport pkg.b as shared\n")
    assert "shadowed_import_alias_target_conflict:consumer:shared" in issues
    assert "pkg.a" not in bindings and "pkg.b" not in bindings


def test_same_source_different_symbol_still_conflicts(monkeypatch):
    _bindings, issues = _local_setup(monkeypatch, "from pkg.a import first as shared\nfrom pkg.a import second as shared\n")
    assert "shadowed_import_alias_target_conflict:consumer:shared" in issues


def test_same_root_unreviewed_external_child_is_not_permitted(monkeypatch):
    source = Path(r"C:\synthetic-root-binding-boundary\consumer.py")
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    monkeypatch.setattr(catalog, "_resolve_local_module_path", lambda _source, name: (None, None))
    monkeypatch.setattr(catalog, "_approved_external_module", lambda name: name == "importlib.util")
    bindings = {"consumer": (source, False)}
    trees = {source: ast.parse("import importlib.util\nimport importlib.not_reviewed\n")}
    issues = set()
    catalog._complete_shadowed_import_module_bindings(bindings, trees, {source: "a"}, frozenset({source}), issues)
    assert "shadowed_import_unresolved:importlib.not_reviewed" in issues


def test_full_local_canonical_names_and_parent_entries_are_preserved(monkeypatch):
    bindings, issues = _local_setup(monkeypatch, "import pkg.a\nimport pkg.b\n")
    assert not issues
    assert set(bindings) == {"consumer", "pkg", "pkg.a", "pkg.b"}


def _authority_fixture(monkeypatch, *, missing=None, existing_first=False, source_text="import pkg.a\nimport pkg.b\n", snapshot_marker="valid", safe_first=False):
    root = Path(r"C:\synthetic-import-authority")
    source, package, first, second = root / "consumer.py", root / "__init__.py", root / "a.py", root / "b.py"
    targets = {"pkg": package, "pkg.a": first, "pkg.b": second}
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    monkeypatch.setattr(catalog, "_resolve_local_module_path", lambda _source, name: (targets.get(name), None))
    bindings = {"consumer": (source, False), "pkg": (package, True), "pkg.b": (second, False)}
    if existing_first:
        bindings["pkg.a"] = (first, False)
    # 実行不能な人工ASTとしてのみ保持する。import・compile・evalしない。
    trees = {source: ast.parse(source_text), package: ast.parse(""), first: ast.parse("" if safe_first else "import socket\nsocket.socket()\ndef safe(data):\n return {}"), second: ast.parse("")}
    files = {source: "a", package: "b", first: "c", second: "d"}
    imported = set(files)
    if missing is not None:
        imported.remove({"source": source, "package": package, "first": first, "second": second}[missing])
    snapshot = frozenset(imported)
    if snapshot_marker == "unknown_path":
        snapshot = frozenset(imported | {root / "unknown.py"})
    elif snapshot_marker != "valid":
        snapshot = {"none": None, "dict": {}, "set": imported}[snapshot_marker]
    issues = set()
    catalog._complete_shadowed_import_module_bindings(bindings, trees, files, snapshot, issues)
    return bindings, issues


def test_callee_only_registered_source_cannot_gain_module_name(monkeypatch):
    bindings, issues = _authority_fixture(monkeypatch, missing="first")
    assert "pkg.a" not in bindings
    assert "shadowed_import_source_not_import_audited:pkg.a" in issues


def test_registered_only_parent_package_rejects_child_completion(monkeypatch):
    bindings, issues = _authority_fixture(monkeypatch, missing="package")
    assert "pkg.a" not in bindings
    assert "shadowed_import_source_not_import_audited:pkg" in issues


def test_registered_only_existing_binding_is_not_import_authority(monkeypatch):
    _bindings, issues = _authority_fixture(monkeypatch, missing="first", existing_first=True)
    assert "shadowed_import_source_not_import_audited:pkg.a" in issues


def test_registered_only_entry_is_not_processed(monkeypatch):
    bindings, issues = _authority_fixture(monkeypatch, missing="source")
    assert "pkg.a" not in bindings
    assert "shadowed_import_source_not_import_audited:consumer" in issues


def test_from_package_registered_only_child_is_not_added(monkeypatch):
    bindings, issues = _authority_fixture(monkeypatch, missing="first", source_text="from pkg import a\n")
    assert "pkg.a" not in bindings
    assert "shadowed_import_source_not_import_audited:pkg.a" in issues


@pytest.mark.parametrize("marker", ["none", "dict", "set", "unknown_path"])
def test_unavailable_import_audit_snapshot_is_rejected(monkeypatch, marker):
    bindings, issues = _authority_fixture(monkeypatch, snapshot_marker=marker)
    assert issues == {"shadowed_import_import_audit_snapshot_unavailable"}
    assert "pkg.a" not in bindings


def test_all_sources_import_audited_preserve_canonical_completion(monkeypatch):
    bindings, issues = _authority_fixture(monkeypatch, safe_first=True)
    assert not issues
    assert "pkg.a" in bindings


def test_callee_only_source_must_not_gain_module_import_authority(tmp_path, monkeypatch):
    """network呼出しはAST文字列だけであり、人工moduleをimportしない。"""
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "a.py").write_text("import socket\nsocket.socket()\ndef safe(data):\n return {}\n", encoding="utf-8")
    (package / "b.py").write_text("def safe(data):\n return {}\n", encoding="utf-8")
    consumer = tmp_path / "consumer.py"
    consumer.write_text("import pkg.a\nimport pkg.b\ndef extract(data):\n return pkg.a.safe(data)\n", encoding="utf-8")
    entry = tmp_path / "entry.py"
    entry.write_text("from consumer import extract\ndef invoke(data):\n return extract(data)\n", encoding="utf-8")
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(catalog, "FRAMEWORK_ROOT", tmp_path / "analysis-framework")
    monkeypatch.setattr(catalog, "MALWARE_ROOT", tmp_path / "analysis-framework" / "malware")
    catalog._resolve_local_module_path.cache_clear()
    try:
        audit = catalog._recursive_handler_side_effect_audit(entry, "invoke")
    finally:
        catalog._resolve_local_module_path.cache_clear()
    new_names = {item["name"] for item in audit["module_bindings"]}
    assert "pkg.a" not in new_names
    assert audit["calls_inspected"] == 2
    assert {item["path"] for item in audit["files"]} == {"entry.py", "consumer.py", "pkg/__init__.py", "pkg/a.py", "pkg/b.py"}
    assert "shadowed_import_source_not_import_audited:pkg.a" in audit["issues"], audit
