"""FormBook／XLoader解析鍵の安全な入力方法を検証する。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "formbook_loader"
    / "native_xloader.py"
)
SPEC = importlib.util.spec_from_file_location(
    "native_xloader_private_key_test", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
NATIVE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = NATIVE
SPEC.loader.exec_module(NATIVE)


def test_private_hex_key_file_is_decoded(tmp_path: Path) -> None:
    key_file = tmp_path / "key.hex"
    key_file.write_text("0011AAbb\n", encoding="ascii")

    assert NATIVE.read_private_key_material(key_file) == b"\x00\x11\xaa\xbb"


def test_repository_key_file_is_rejected() -> None:
    with pytest.raises(ValueError, match="repository外"):
        NATIVE.read_private_key_material(MODULE_PATH)
