"""上限付きWannaCry W/101復元の回帰試験。"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest


MODULE_PATH = Path(__file__).parents[1] / "malware" / "wannacry" / "extract_config.py"
SPEC = importlib.util.spec_from_file_location("wannacry_extract_config", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_embedded_worm_accepts_explicitly_truncated_resource() -> None:
    payload = b"MZ" + b"A" * 30
    recovered, declared_size, complete = MODULE._embedded_worm(
        struct.pack("<I", 128) + payload
    )
    assert recovered == payload
    assert declared_size == 128
    assert complete is False


def test_embedded_worm_rejects_non_pe_and_empty_resource() -> None:
    with pytest.raises(ValueError):
        MODULE._embedded_worm(b"\x00\x00\x00")
    with pytest.raises(ValueError):
        MODULE._embedded_worm(struct.pack("<I", 4) + b"NOPE")


def test_expected_pe_extent_uses_largest_section_end() -> None:
    image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(SizeOfHeaders=0x400),
        sections=[
            SimpleNamespace(PointerToRawData=0x400, SizeOfRawData=0x600),
            SimpleNamespace(PointerToRawData=0xA00, SizeOfRawData=0x200),
        ],
    )
    assert MODULE._pe_expected_extent(image) == 0xC00
