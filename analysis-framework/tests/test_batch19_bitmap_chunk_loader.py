from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import zlib

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def rgba_png(width: int, height: int, rgba: bytes) -> bytes:
    assert len(rgba) == width * height * 4
    rows = b"".join(
        b"\x00" + rgba[row * width * 4 : (row + 1) * width * 4]
        for row in range(height)
    )
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(rows))
        + png_chunk(b"IEND", b"")
    )


def test_png_bgra_and_reviewed_chunk_envelope() -> None:
    module = load(
        "analysis-framework/malware/dotnet_resource_loader/bitmap_chunk_loader.py",
        "batch19_bitmap_chunk",
    )
    # RGBAからBGRAへ変換すると、長さ1・区切り0xaa・payload 0x5aになる。
    png = rgba_png(2, 1, bytes((0, 0, 1, 0, 0, 0x5A, 0xAA, 0)))
    pixels, metadata = module.decode_png_bgra(png)
    assert pixels == bytes((1, 0, 0, 0, 0xAA, 0x5A, 0, 0))
    assert metadata["width"] == 2
    chunk, chunk_metadata = module.extract_chunk(png)
    assert chunk == b"\x5a"
    assert chunk_metadata["payload_length"] == 1


def test_quicklz_level3_uncompressed_frame() -> None:
    module = load("analysis-framework/common/quicklz.py", "batch19_quicklz")
    payload = b"MZ" + bytes(range(32))
    flags = (3 << 2) | 2
    frame = bytes((flags,)) + struct.pack("<II", 9 + len(payload), len(payload)) + payload
    header = module.parse_header(frame)
    assert header["level"] == 3
    assert header["is_compressed"] is False
    assert module.decompress(frame) == payload


def test_weak_xor_is_reversible_and_unknown_parent_fails_closed() -> None:
    module = load(
        "analysis-framework/malware/dotnet_resource_loader/bitmap_chunk_loader.py",
        "batch19_bitmap_chunk_closed",
    )
    original = bytes(range(128))
    assert module.weak_xor(module.weak_xor(original)) == original
    with pytest.raises(ValueError, match="SHA-256"):
        module.extract_config(b"synthetic")


def test_png_crc_mismatch_is_rejected() -> None:
    module = load(
        "analysis-framework/malware/dotnet_resource_loader/bitmap_chunk_loader.py",
        "batch19_bitmap_chunk_crc",
    )
    png = bytearray(rgba_png(1, 1, b"\x00\x00\x00\x00"))
    png[-1] ^= 1
    with pytest.raises(ValueError, match="CRC"):
        module.decode_png_bgra(bytes(png))
