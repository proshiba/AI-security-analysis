"""通常C2契約のfile参照を人工filesystemだけで検証する。"""
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

DIGEST = "a" * 64
ROOT = Path(r"C:\audit_repository") if Path("C:/").is_absolute() else Path("/audit_repository")
DIR = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0)
FILE = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_file_attributes=0)


def _document():
    result = target.build_unresolved_contract(DIGEST, "fixture")
    result["automation"]["handlers"] = ["handler.py"]
    result["automation"]["tests"] = ["test_handler.py"]
    return result


def _fake_fs(monkeypatch, *, file_error=None):
    def fake_lstat(self, *args, **kwargs):
        return DIR if self == ROOT else FILE
    def fake_resolve(self, *args, **kwargs):
        return self
    def fake_is_file(self, *args, **kwargs):
        if file_error is not None:
            raise file_error
        return True
    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(Path, "resolve", fake_resolve)
    monkeypatch.setattr(Path, "is_file", fake_is_file)


def test_deferred_contract_stays_deferred_for_valid_contained_references(monkeypatch):
    with monkeypatch.context() as patch:
        _fake_fs(patch)
        result = target.validate_contract(_document(), DIGEST, repository=ROOT)
    assert result["complete"] is False
    assert result["daily_ready"] is True
    assert result["deferred"] is True


@pytest.mark.parametrize("error", [OSError("人工"), ValueError("人工"), RuntimeError("人工")])
def test_file_check_error_becomes_daily_blocking_path_finding(monkeypatch, error):
    with monkeypatch.context() as patch:
        _fake_fs(patch, file_error=error)
        result = target.validate_contract(_document(), DIGEST, repository=ROOT)
    assert result["complete"] is False
    assert result["daily_ready"] is False
    assert result["deferred"] is False
    codes = {item["code"] for item in result["findings"]}
    assert "c2_automation_handlers_path" in codes
    assert "c2_automation_tests_path" in codes


def test_external_reference_becomes_path_finding_without_lookup(monkeypatch):
    document = _document()
    document["automation"]["handlers"] = [r"\\audit-invalid.example\share\handler.py"]
    document["automation"]["tests"] = [r"D:\outside\test_handler.py"]
    def forbidden(self, *args, **kwargs):
        raise AssertionError("外部候補について実lookupをしてはいけない")
    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", forbidden)
        patch.setattr(Path, "resolve", forbidden)
        patch.setattr(Path, "is_file", forbidden)
        result = target.validate_contract(document, DIGEST, repository=ROOT)
    assert result["complete"] is False
    assert result["daily_ready"] is False
    codes = {item["code"] for item in result["findings"]}
    assert "c2_automation_handlers_path" in codes
    assert "c2_automation_tests_path" in codes


def test_repository_none_keeps_old_no_path_check_semantics(monkeypatch):
    def forbidden(self, *args, **kwargs):
        raise AssertionError("repositoryなしでは実lookupをしてはいけない")
    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", forbidden)
        patch.setattr(Path, "resolve", forbidden)
        patch.setattr(Path, "is_file", forbidden)
        result = target.validate_contract(_document(), DIGEST)
    assert result["complete"] is False
    assert result["daily_ready"] is True
