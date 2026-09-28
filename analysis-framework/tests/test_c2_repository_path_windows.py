"""JSON由来の参照文字列を人工metadataだけで反対側から点検する。"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "common" / "c2_analysis_contract.py"
SPEC = importlib.util.spec_from_file_location("_independent_c2_path_guard", SOURCE)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)
pytestmark = pytest.mark.skipif(not Path("C:/").is_absolute(), reason="Windows固有namespaceはWindows上で確認する")
ROOT = Path(r"C:\audit_repository")
DIR = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0)
FILE = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_file_attributes=0)


def _metadata(monkeypatch, *, changed=None, resolution=None):
    calls = []
    changed = changed or {}
    def lstat(self, *args, **kwargs):
        calls.append(("lstat", self))
        return changed.get(self, FILE if self.name.endswith(".py") else DIR)
    def resolve(self, *args, **kwargs):
        calls.append(("resolve", self))
        return resolution.get(self, self) if resolution is not None else self
    def present(self, *args, **kwargs):
        calls.append(("is_file", self))
        return self.name.endswith(".py")
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "is_file", present)
    return calls


@pytest.mark.parametrize("value", [
    r"\??\C:\audit_repository\handler.py",
    r"\Device\HarddiskVolume1\handler.py",
    r"\\?\GLOBALROOT\Device\HarddiskVolume1\handler.py",
    r"\\.\GLOBALROOT\Device\HarddiskVolume1\handler.py",
    "//?/C:/audit_repository/handler.py",
    "//./C:/audit_repository/handler.py",
    r"\\server.invalid\c$\handler.py",
    r"/audit_repository/handler.py",
    r"C:handler.py",
    r"C:\audit_repository\a\..\..\outside\handler.py",
    r"C:\audit_repository\..\audit_repository\handler.py",
    r"C:\audit_repository_extra\handler.py",
    r"handler.py::$DATA",
    r"a\..\handler.py:$INDEX_ALLOCATION",
    r"a\.. \handler.py",
    r"...\handler.py",
    r"a\LPT³.py",
    r"a\COM2 .py",
    r"a\CONIN$.txt",
    r"a\NUL.aux\..\handler.py",
    "a/\x1f/handler.py",
    "file://server.invalid/share/handler.py",
])
def test_extra_windows_lexical_forms_reject_before_metadata(monkeypatch, value):
    with monkeypatch.context() as patch:
        calls = _metadata(patch)
        assert target._repository_path(ROOT, value) is None
    assert calls == []


@pytest.mark.parametrize("value", [r"a\..\b\..\handler.py", r"a\.\..\handler.py",
                                      r"c:\AUDIT_REPOSITORY\handler.py", "normal..name.py"])
def test_valid_lexical_aliases_stay_inside_trusted_root(monkeypatch, value):
    with monkeypatch.context() as patch:
        calls = _metadata(patch)
        result = target._repository_path(ROOT, value)
    assert result is not None
    result.relative_to(ROOT)
    assert calls[0] == ("lstat", ROOT)
    assert all(path == ROOT or ROOT in path.parents for _kind, path in calls)


@pytest.mark.parametrize("count,accepted", [(128, True), (129, False)])
def test_component_budget_boundary(monkeypatch, count, accepted):
    value = "/".join(["a"] * (count - 1) + ["handler.py"])
    with monkeypatch.context() as patch:
        calls = _metadata(patch)
        result = target._repository_path(ROOT, value)
    assert (result is not None) is accepted
    if accepted:
        assert sum(kind == "lstat" for kind, _path in calls) == count + 1
    else:
        assert calls == []


@pytest.mark.parametrize("length,accepted", [(4096, True), (4097, False)])
def test_character_budget_boundary_with_no_real_long_path_lookup(monkeypatch, length, accepted):
    value = "a" * (length - 3) + ".py"
    with monkeypatch.context() as patch:
        calls = _metadata(patch)
        result = target._repository_path(ROOT, value)
    assert (result is not None) is accepted
    if not accepted:
        assert calls == []


def test_noncanonical_trusted_root_is_rejected_before_metadata(monkeypatch):
    with monkeypatch.context() as patch:
        calls = _metadata(patch)
        assert target._repository_path(ROOT / "a" / "..", "handler.py") is None
    assert calls == []


def test_regular_file_reparse_flag_is_not_followed(monkeypatch):
    flagged = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_file_attributes=0x400)
    with monkeypatch.context() as patch:
        calls = _metadata(patch, changed={ROOT / "handler.py": flagged})
        assert target._repository_path(ROOT, "handler.py") is None
    assert calls == [("lstat", ROOT), ("lstat", ROOT / "handler.py")]


def test_fixed_state_resolution_escape_is_not_a_valid_file(monkeypatch):
    with monkeypatch.context() as patch:
        calls = _metadata(patch, resolution={ROOT / "handler.py": ROOT.parent / "outside" / "handler.py"})
        resolved = target._repository_path(ROOT, "handler.py")
        assert resolved is None
        assert target._repository_file_present(resolved) is False
    assert not any(kind == "is_file" for kind, _path in calls)
