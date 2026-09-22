"""Inno暗号化内層の非実行復元境界を検証する。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "protected_installer_bundle"
    / "inno_static.py"
)
SPEC = importlib.util.spec_from_file_location("valleyrat_inno_static_test", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_script_candidates_are_static_literals_only() -> None:
    script = "Assign LocalVar1 := 'abcdefghijklmnop'\nCall ExpandConstant\n"
    assert MODULE.script_password_candidates(script) == ("abcdefghijklmnop",)
    assert MODULE.script_password_candidates("Call TAC\n") == ()


def test_static_recovery_never_calls_script_emulator(monkeypatch: pytest.MonkeyPatch) -> None:
    import refinery.lib.inno.archive as archive_module

    expected = b"MZ synthetic inert fixture"
    item = SimpleNamespace(path="data/test.dll", size=len(expected), encrypted=True, dupe=False)

    class FakeScript:
        def disassembly(self) -> str:
            return "Assign LocalVar1 := 'abcdefghijklmnop'"

    class FakeArchive:
        files = [item]
        ifps = FakeScript()

        def __init__(self, data: bytearray):
            assert data == b"safe synthetic container"

        def read_file_and_check(self, file: object, password: str | None) -> bytes:
            assert file is item
            assert password == "abcdefghijklmnop"
            return expected

        def guess_password(self, timeout: int) -> bool:
            raise AssertionError("PascalScript emulator must not run")

    monkeypatch.setattr(archive_module, "InnoArchive", FakeArchive)
    summary, recovered = MODULE.recover_members(b"safe synthetic container")
    assert summary["status"] == "recovered"
    assert summary["recovered_member_count"] == 1
    assert summary["safety"]["script_emulated"] is False
    assert "abcdefghijklmnop" not in str(summary)
    assert recovered == [("data/test.dll", expected)]


def test_private_writer_rejects_repository_tree(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="リポジトリ"):
        MODULE._write_private_members(MODULE_PATH.parent, [("data/test.dll", b"MZ")])
    outside = tmp_path / "private"
    MODULE._write_private_members(outside, [("data/test.dll", b"MZ")])
    assert len(list(outside.glob("*.quarantine.bin"))) == 1


def test_input_and_candidate_bounds() -> None:
    with pytest.raises(ValueError, match="サイズ上限"):
        MODULE.recover_members(b"x" * (MODULE.MAX_INPUT_SIZE + 1))
    literals = "\n".join(f"Assign LocalVar1 := '{i:08d}'" for i in range(33))
    with pytest.raises(ValueError, match="候補上限"):
        MODULE.script_password_candidates(literals)
