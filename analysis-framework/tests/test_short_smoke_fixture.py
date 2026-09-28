"""人工smoke専用fixtureが固定file以外の保護を解除しないことを確認する。"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

# pytestのimportlib modeでは兄弟testのbare名がsys.modulesへ登録されない。
# 検証するfixtureは固定した通常test fileから読み、sys.pathへ依存させない。
_fixture_source = Path(__file__).with_name("test_analysis_job_runner.py")
_fixture_spec = importlib.util.spec_from_file_location("_short_smoke_fixture_reference", _fixture_source)
assert _fixture_spec is not None and _fixture_spec.loader is not None
_fixture_module = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture_module)
short_smoke_root = _fixture_module.short_smoke_root


def _snapshot(root: Path) -> Path:
    path = (root / "jobs" / "job-real-smoke" / "contract-inputs"
            / "samples" / "000000" / "sample.bin")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"artificial test fixture")
    return path


def test_missing_fixed_snapshot_needs_no_permission_change(tmp_path, monkeypatch):
    generator = short_smoke_root.__wrapped__(tmp_path)
    assert next(generator) == tmp_path
    def forbidden(*args):
        raise AssertionError("存在しないsnapshotの権限を変更してはいけない")
    monkeypatch.setattr(os, "chmod", forbidden)
    with pytest.raises(StopIteration):
        next(generator)


def test_fixed_readonly_snapshot_is_preserved_until_teardown(tmp_path):
    generator = short_smoke_root.__wrapped__(tmp_path)
    assert next(generator) == tmp_path
    path = _snapshot(tmp_path)
    os.chmod(path, stat.S_IREAD)
    assert not path.stat().st_mode & stat.S_IWRITE
    with pytest.raises(StopIteration):
        next(generator)
    assert path.stat().st_mode & stat.S_IWRITE


@pytest.mark.parametrize("mode,links,attributes", [
    (stat.S_IFDIR, 1, 0), (stat.S_IFREG, 2, 0), (stat.S_IFREG, 1, 0x400),
])
def test_nonregular_multilink_or_reparse_snapshot_is_not_changed(
    tmp_path, monkeypatch, mode, links, attributes,
):
    generator = short_smoke_root.__wrapped__(tmp_path)
    assert next(generator) == tmp_path
    path = _snapshot(tmp_path)
    original = Path.lstat
    def metadata(self, *args, **kwargs):
        if self == path:
            return SimpleNamespace(st_mode=mode, st_nlink=links,
                                   st_file_attributes=attributes)
        return original(self, *args, **kwargs)
    def forbidden(*args):
        raise AssertionError("不正なsnapshotの権限を変更してはいけない")
    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", metadata)
        patch.setattr(os, "chmod", forbidden)
        with pytest.raises(RuntimeError, match="通常単一file"):
            next(generator)


def test_resolution_outside_fixture_root_is_not_changed(tmp_path, monkeypatch):
    generator = short_smoke_root.__wrapped__(tmp_path)
    assert next(generator) == tmp_path
    path = _snapshot(tmp_path)
    original = Path.resolve
    def resolve(self, *args, **kwargs):
        return tmp_path.parent / "outside-artificial.bin" if self == path else original(self, *args, **kwargs)
    def forbidden(*args):
        raise AssertionError("fixture外のfileの権限を変更してはいけない")
    with monkeypatch.context() as patch:
        patch.setattr(Path, "resolve", resolve)
        patch.setattr(os, "chmod", forbidden)
        with pytest.raises(ValueError):
            next(generator)
