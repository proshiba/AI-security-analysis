from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "analysis-framework/malware/dotnet_resource_loader/bitmap_column_loader.py"
    spec = importlib.util.spec_from_file_location("batch19_bitmap_column", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_bmp() -> bytes:
    width, height = 2, 2
    pixels = bytes(
        [
            3, 2, 1, 255,
            6, 5, 4, 255,
            9, 8, 7, 255,
            12, 11, 10, 255,
        ]
    )
    size = 54 + len(pixels)
    header = bytearray(54)
    header[:2] = b"BM"
    header[2:6] = size.to_bytes(4, "little")
    header[10:14] = (54).to_bytes(4, "little")
    header[14:18] = (40).to_bytes(4, "little")
    header[18:22] = width.to_bytes(4, "little", signed=True)
    header[22:26] = height.to_bytes(4, "little", signed=True)
    header[26:28] = (1).to_bytes(2, "little")
    header[28:30] = (32).to_bytes(2, "little")
    return bytes(header) + pixels


def test_column_major_getpixel_order_is_reproduced() -> None:
    module = load_module()
    child, metadata = module.decode_bmp_column_rgb(make_bmp(), expected_dimensions=(2, 2))
    assert child == bytes([7, 8, 9, 1, 2, 3, 10, 11, 12, 4, 5, 6])
    assert metadata["width"] == 2


def test_extractor_rejects_unreviewed_hash() -> None:
    module = load_module()
    with pytest.raises(ValueError, match="SHA-256"):
        module.extract_config(b"synthetic")
