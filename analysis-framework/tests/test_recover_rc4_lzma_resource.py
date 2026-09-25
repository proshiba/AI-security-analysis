from __future__ import annotations

import importlib.util
import lzma
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "common" / "recover_rc4_lzma_resource.py"
SPEC = importlib.util.spec_from_file_location("recover_rc4_lzma_resource", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_rc4_and_lzma_round_trip_without_executing_payload() -> None:
    payload = b"MZ" + b"\0" * 2048
    compressed = lzma.compress(payload, format=lzma.FORMAT_ALONE)
    encrypted = MODULE.rc4_decrypt(compressed, b"test-key")
    assert MODULE.rc4_decrypt(encrypted, b"test-key") == compressed
    assert MODULE.decompress_lzma_alone(
        MODULE.rc4_decrypt(encrypted, b"test-key"), maximum=4096
    ) == payload


def test_lzma_output_limit_and_empty_key_fail_closed() -> None:
    with pytest.raises(ValueError):
        MODULE.rc4_decrypt(b"data", b"")
    compressed = lzma.compress(b"MZ" + b"x" * 4096, format=lzma.FORMAT_ALONE)
    with pytest.raises(ValueError):
        MODULE.decompress_lzma_alone(compressed, maximum=100)
