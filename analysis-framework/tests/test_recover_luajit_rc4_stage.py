"""LuaJIT RC4後段復元器の非実行・上限・形式検証を確認する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "common" / "recover_luajit_rc4_stage.py"
SPEC = importlib.util.spec_from_file_location("recover_luajit_rc4_stage", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_rc4_known_vector() -> None:
    """既知のRC4 test vectorと対称復号を確認する。"""

    key = b"Keyxxxxx"
    clear = b"Plaintext"
    encrypted = module.rc4_transform(clear, key)
    assert module.rc4_transform(encrypted, key) == clear
    assert encrypted != clear


def test_loader_anchors_and_candidate_cap() -> None:
    """無関係なbyte列と過大な鍵候補を拒否する。"""

    with pytest.raises(module.RecoveryRejected):
        module.key_candidates(b"not bytecode")
    anchors = b"\x1bLJ\x02 VirtualAlloc VirtualProtect CreateThread "
    assert module.key_candidates(anchors + b"s3ch0bachky") == [b"s3ch0bachky"]
    many = b" ".join(f"key{i:08d}".encode() for i in range(module.MAX_KEY_CANDIDATES + 1))
    with pytest.raises(module.RecoveryRejected):
        module.key_candidates(anchors + many)


def test_random_mz_is_not_valid_pe() -> None:
    """MZ文字列のみで後段PEと誤認しない。"""

    assert module.find_embedded_pe(b"X" * 20 + b"MZ" + b"Y" * 5000) is None
