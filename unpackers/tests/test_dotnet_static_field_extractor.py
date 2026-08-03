from __future__ import annotations

import struct

import pytest

from unpackers import dotnet_static_field_extractor as extractor


def _metadata_root() -> bytes:
    version = b"v4.0.30319\0\0"
    root = bytearray(b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version)
    while len(root) % 4:
        root.append(0)
    root += struct.pack("<HH", 0, 2)
    root += struct.pack("<II", 64, 4) + b"#~\0\0"
    root += struct.pack("<II", 68, 4) + b"#Strings\0\0\0"
    if len(root) < 72:
        root += b"\0" * (72 - len(root))
    return bytes(root)


def test_metadata_root_accepts_required_streams() -> None:
    data = _metadata_root()
    size, streams = extractor._metadata_root(data, 0)

    assert size == 72
    assert streams == ("#~", "#Strings")


def test_metadata_root_rejects_out_of_bounds_stream() -> None:
    data = bytearray(_metadata_root())
    struct.pack_into("<II", data, 36, 0xFFFF, 4)

    with pytest.raises(extractor.ManagedMetadataError, match="範囲"):
        extractor._metadata_root(bytes(data), 0)


def test_rejects_non_pe() -> None:
    with pytest.raises(extractor.ManagedMetadataError, match="PE"):
        extractor.prepare_managed_view(b"not a managed PE")
