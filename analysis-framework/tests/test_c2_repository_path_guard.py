"""通常source／固定人工sentinel／正常local tempfileのみを使う移植可能な試験。"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

MODULE = Path(__file__).resolve().parents[1] / "common" / "c2_analysis_contract.py"
SPEC = importlib.util.spec_from_file_location("_c2_repository_path_guard", MODULE)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)

ROOT = Path(r"C:\audit_repository") if Path().anchor != "/" and Path("C:/").is_absolute() else Path("/audit_repository")
DIR = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0)
FILE = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_file_attributes=0)
REPARSE = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0x400)
SYMLINK = SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_file_attributes=0)


def _fake_filesystem(monkeypatch, *, overrides=None, errors=None):
    calls = []
    overrides = overrides or {}
    errors = errors or {}

    def fake_lstat(self, *args, **kwargs):
        calls.append(("lstat", self))
        if ("lstat", self) in errors:
            raise errors[("lstat", self)]
        return overrides.get(self, FILE if self.name.endswith(".py") else DIR)

    def fake_resolve(self, *args, **kwargs):
        calls.append(("resolve", self))
        if ("resolve", self) in errors:
            raise errors[("resolve", self)]
        return self

    def fake_is_file(self, *args, **kwargs):
        calls.append(("is_file", self))
        if ("is_file", self) in errors:
            raise errors[("is_file", self)]
        return self.name.endswith(".py")

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(Path, "resolve", fake_resolve)
    monkeypatch.setattr(Path, "is_file", fake_is_file)
    return calls


@pytest.mark.parametrize("value", [
    r"\\audit-invalid.example\share\handler.py",
    "//audit-invalid.example/share/handler.py",
    r"D:\outside\handler.py",
    r"D:outside\handler.py",
    r"\outside\handler.py",
    r"..\outside\handler.py" if ROOT.drive else "../outside/handler.py",
    r"\\?\UNC\audit-invalid.example\share\handler.py",
    r"\\?\D:\outside\handler.py",
    r"\\.\pipe\audit-invalid",
])
def test_outside_and_ambiguous_reference_has_no_filesystem_calls(monkeypatch, value):
    if not ROOT.drive and value == r"\outside\handler.py":
        pytest.skip("Windows root-relative の意味は Windows だけで確認する")
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch)
        result = target._repository_path(ROOT, value)
    assert result is None
    assert calls == []


@pytest.mark.parametrize("value", [
    "CON", "con.py", "NUL", "AUX.txt", "PRN", "CONIN$", "CONOUT$",
    "COM1.py", "LPT9", "COM¹", "LPT².txt", "COM³.py", "CON .py",
    "handler.py.", "handler.py ", "handler.py:stream", "bad?name.py",
    "bad*name.py", "bad|name.py", "bad\x01.py", "NUL/../handler.py",
])
def test_windows_namespace_aliases_are_rejected_before_lookup(monkeypatch, value):
    if not ROOT.drive:
        pytest.skip("Windows namespace の意味は Windows で確認する")
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch)
        result = target._repository_path(ROOT, value)
    assert result is None
    assert calls == []


@pytest.mark.parametrize("value", ["console.py", "COM10.py", "LPT0.py", "name..py"])
def test_normal_names_are_not_rewritten_or_over_rejected(monkeypatch, value):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch)
        result = target._repository_path(ROOT, value)
    assert result == ROOT / value
    assert ("lstat", ROOT / value) in calls


@pytest.mark.parametrize("value", ["handler.py", "a/../handler.py", str(ROOT / "handler.py")])
def test_contained_reference_compatibility(monkeypatch, value):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch)
        result = target._repository_path(ROOT, value)
    assert result == ROOT / "handler.py"
    assert calls[0] == ("lstat", ROOT)
    if ".." in value:
        assert ("lstat", ROOT / "a") in calls


@pytest.mark.parametrize("info", [REPARSE, SYMLINK])
@pytest.mark.parametrize("value", ["linked/handler.py", "linked/../handler.py", "linked.py"])
def test_reparse_is_rejected_without_following_or_skipping_dotdot(monkeypatch, info, value):
    component = ROOT / ("linked.py" if value == "linked.py" else "linked")
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch, overrides={component: info})
        result = target._repository_path(ROOT, value)
    assert result is None
    assert calls == [("lstat", ROOT), ("lstat", component)]


@pytest.mark.parametrize("info", [REPARSE, SYMLINK, FILE])
def test_untrusted_root_is_rejected(monkeypatch, info):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch, overrides={ROOT: info})
        result = target._repository_path(ROOT, "handler.py")
    assert result is None
    assert calls == [("lstat", ROOT)]


@pytest.mark.parametrize("error", [OSError("人工"), ValueError("人工"), RuntimeError("人工")])
@pytest.mark.parametrize("operation,path", [
    ("lstat", ROOT), ("lstat", ROOT / "handler.py"),
    ("resolve", ROOT), ("resolve", ROOT / "handler.py"),
])
def test_metadata_or_resolution_failure_is_none(monkeypatch, error, operation, path):
    with monkeypatch.context() as patch:
        _fake_filesystem(patch, errors={(operation, path): error})
        result = target._repository_path(ROOT, "handler.py")
    assert result is None


@pytest.mark.parametrize("error", [OSError("人工"), ValueError("人工"), RuntimeError("人工")])
def test_file_check_failure_is_false(monkeypatch, error):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch, errors={("is_file", ROOT / "handler.py"): error})
        result = target._repository_file_present(ROOT / "handler.py")
    assert result is False
    assert calls == [("is_file", ROOT / "handler.py")]


@pytest.mark.parametrize("value", [None, 1, "", "   ", "bad\x00.py", "x" * 4097, "/".join(["a"] * 129)])
def test_invalid_or_over_budget_input_never_touches_filesystem(monkeypatch, value):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch)
        result = target._repository_path(ROOT, value)
    assert result is None
    assert calls == []


def test_prefix_similar_root_is_not_contained(monkeypatch):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch)
        result = target._repository_path(ROOT, str(ROOT.with_name(ROOT.name + "2") / "handler.py"))
    assert result is None
    assert calls == []


def test_escape_then_return_is_rejected_before_metadata(monkeypatch):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch)
        result = target._repository_path(ROOT, "../" + ROOT.name + "/handler.py")
    assert result is None
    assert calls == []


def test_non_directory_before_dotdot_fails(monkeypatch):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch, overrides={ROOT / "a": FILE})
        result = target._repository_path(ROOT, "a/../handler.py")
    assert result is None
    assert calls == [("lstat", ROOT), ("lstat", ROOT / "a")]


def test_resolution_escape_after_metadata_revalidation_is_rejected(monkeypatch):
    with monkeypatch.context() as patch:
        calls = _fake_filesystem(patch)
        def fake_escape(self, *args, **kwargs):
            calls.append(("resolve", self))
            return ROOT.parent / "outside" / "handler.py" if self != ROOT else ROOT
        patch.setattr(Path, "resolve", fake_escape)
        result = target._repository_path(ROOT, "handler.py")
    assert result is None
    assert ("resolve", ROOT / "handler.py") in calls


def test_normal_local_tempfile_compatibility(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "handler.py").write_text("# 人工の通常source\n", encoding="utf-8")
    for value in ("handler.py", "a/../handler.py", str(tmp_path / "handler.py")):
        result = target._repository_path(tmp_path, value)
        assert result == tmp_path / "handler.py"
        assert target._repository_file_present(result) is True
    assert target._repository_path(tmp_path, "missing.py") is None
    assert target._repository_file_present(None) is False
