"""通常sourceのAST監査と人工sourceだけで、限定depth修正を点検する。"""

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


def _normal_roots(module, monkeypatch):
    for name, path in {"REPOSITORY_ROOT": ROOT, "FRAMEWORK_ROOT": ROOT / "analysis-framework",
                       "MALWARE_ROOT": ROOT / "analysis-framework" / "malware",
                       "EXTRACTORS_ROOT": ROOT / "extractors",
                       "PROFILE_PATH": ROOT / "extractors" / "profiles" / "windows_family_profiles.json"}.items():
        monkeypatch.setattr(module, name, path)
    module.clear_handler_caches()


@pytest.mark.parametrize("handler_id", [
    "asyncrat:extractors.asyncrat.extractor.py:extract",
    "donutloader:extractors.donutloader.extractor.py:extract",
    "purehvnc:analysis.framework.malware.purehvnc.extract.config.py:extract_config",
    "purehvnc:extractors.purehvnc.extractor.py:extract",
])
def test_normal_managed_preflight_after_structural_depth_removal(monkeypatch, handler_id):
    _normal_roots(catalog, monkeypatch)
    specs = {spec.id: spec for spec in catalog.discover_handlers()}
    result = catalog.preflight_handler_for_assessment(specs[handler_id], actual_format="pe", input_size=1)
    assert catalog.MAX_ASSESSMENT_IMPORT_DEPTH == 12
    assert result["eligible"] is True, result["blockers"]
    assert result["blockers"] == []
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False


def test_real_import_depth_limit_is_not_relaxed(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    root.mkdir()
    for index in range(14):
        suffix = f"import m{index + 1}\n" if index < 13 else ""
        (root / f"m{index}.py").write_text(suffix + "def entry():\n    return None\n", encoding="utf-8")
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", root)
    result = catalog._recursive_handler_side_effect_audit(root / "m0.py", "entry")
    assert catalog.MAX_ASSESSMENT_IMPORT_DEPTH == 12
    assert "import_depth_limit:m13.py" in result["issues"]


def test_same_file_long_callee_chain_body_is_not_skipped(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    root.mkdir()
    definitions = ["def entry():\n    return f1()\n"]
    for index in range(1, 15):
        tail = f"f{index + 1}()" if index < 14 else 'open("synthetic-only", "rb")'
        definitions.append(f"def f{index}():\n    return {tail}\n")
    source = root / "callee_chain.py"
    source.write_text("\n".join(definitions), encoding="utf-8")
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", root)
    result = catalog._recursive_handler_side_effect_audit(source, "entry")
    assert catalog.MAX_ASSESSMENT_IMPORT_DEPTH == 12
    assert any("forbidden" in issue or "unapproved" in issue for issue in result["issues"])
    # 既存MAXはregister_fileの境界であり、同fileの全callee bodyを12で打切る規則ではない。
    assert not any("import_depth_limit" in issue for issue in result["issues"])


@pytest.fixture
def copied_closure(tmp_path, monkeypatch):
    root = tmp_path / "repository"
    for relative in (*catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS, *catalog._MANAGED_RESOURCE_CONSUMER_COMMITMENTS,
                     "unpackers/managed_metadata.py", "unpackers/__init__.py"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", root)
    yield root


@pytest.mark.parametrize("shape", ["metadata_constructor", "unused_resource_class_method", "indirect_resource_helper"])
def test_all_body_capability_audit_remains_after_depth_removal(copied_closure, monkeypatch, shape):
    relative = "unpackers/managed_metadata.py" if shape == "metadata_constructor" else "unpackers/managed_resources.py"
    path = copied_closure / relative
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    if shape == "metadata_constructor":
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "MetadataResolver")
        constructor = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
        first = constructor.body[0]
        lines.insert(first.lineno - 1, '        open("synthetic-only", "rb")\n')
    elif shape == "unused_resource_class_method":
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "_ResourceScan")
        lines.insert(owner.end_lineno, '\n    def _synthetic_unused(self):\n        open("synthetic-only", "rb")\n')
    else:
        lines.append('\ndef _synthetic_leaf():\n    open("synthetic-only", "rb")\n\ndef _synthetic_indirect():\n    return _synthetic_leaf()\n')
    path.write_text("".join(lines), encoding="utf-8")
    mapping = (catalog._MANAGED_READER_SOURCE_COMMITMENTS if shape == "metadata_constructor"
               else catalog._MANAGED_RESOURCE_SOURCE_COMMITMENTS)
    monkeypatch.setitem(mapping, relative, hashlib.sha256(path.read_bytes()).hexdigest())
    result = catalog._recursive_handler_side_effect_audit(copied_closure / "unpackers" / "managed_resource_snapshot.py", "prepare_resource_snapshot")
    assert any("forbidden" in issue or "unapproved" in issue for issue in result["issues"]), result
    assert not any("import_depth_limit" in issue for issue in result["issues"])


def test_fixed_allocator_depth_flag_has_one_closed_callsite():
    tree = ast.parse(Path(catalog.__file__).read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "audit_managed_class"
             and any(keyword.arg == "fixed_resource_allocator_entry" for keyword in node.keywords)]
    assert len(calls) == 1
    assert ast.dump(calls[0], include_attributes=False) == ast.dump(ast.parse(
        'audit_managed_class(target, "MetadataResolver", method, depth + 1, context, fixed_resource_allocator_entry=True)',
        mode="eval").body, include_attributes=False)
    definition = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "audit_managed_class")
    assert [argument.arg for argument in definition.args.kwonlyargs] == ["fixed_resource_allocator_entry"]
    assert [ast.dump(value) for value in definition.args.kw_defaults] == ["Constant(value=False)"]


@pytest.mark.parametrize("relative,class_name,method", [
    ("analysis-framework/common/dotnet_rat_config.py", "_LiteralReader", "read"),
    ("unpackers/managed_metadata.py", "_SignatureReader", "type"),
    ("unpackers/managed_metadata.py", "MetadataResolver", "_row"),
])
def test_wrong_fixed_allocator_selection_is_rejected(monkeypatch, relative, class_name, method):
    _normal_roots(catalog, monkeypatch)
    captured = []
    filename = str(Path(catalog.__file__).resolve())

    def profile(frame, event, arg):
        if (event == "call" and frame.f_code.co_name == "audit_managed_class"
                and frame.f_code.co_filename == filename):
            function = frame.f_back.f_locals.get("audit_managed_class")
            if callable(function):
                captured.append(function)
                sys.setprofile(None)

    sys.setprofile(profile)
    try:
        result = catalog._recursive_handler_side_effect_audit(ROOT / "unpackers" / "managed_resource_snapshot.py", "prepare_resource_snapshot")
    finally:
        sys.setprofile(None)
    assert result["issues"] == []
    assert captured
    function = captured[0]
    cells = dict(zip(function.__code__.co_freevars, function.__closure__))
    issues = cells["issues"].cell_contents
    body_auditor = cells["audit_definition"].cell_contents
    body_cells = dict(zip(body_auditor.__code__.co_freevars, body_auditor.__closure__))
    visited = body_cells["visited_definitions"].cell_contents
    body_count = len(visited)
    assert function(ROOT / relative, class_name, method, 2, "synthetic_wrong_selection",
                    fixed_resource_allocator_entry=True) is False
    assert "synthetic_wrong_selection:managed_resource_allocator_class_selection_rejected" in issues
    assert len(visited) == body_count
