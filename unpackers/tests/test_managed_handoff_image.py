"""HOI1 managed handoff imageのbounded parserテスト。"""

from __future__ import annotations

import struct

from unpackers.managed_handoff_image import inspect_managed_handoff_image


def _text(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack("<H", len(encoded)) + encoded


def _blob16(value: bytes) -> bytes:
    return struct.pack("<H", len(value)) + value


def _fixture(*, fixup_offset: int | None = None, version: int = 1) -> bytes:
    data = bytearray(b"HOI1" + struct.pack("<H", version))
    data += _text("Fixture") + _text("Entry")
    data += struct.pack("<H", 1)
    data += struct.pack("<i", 4) + b"DATA"
    data += struct.pack("<H", 1)

    data += _text("Entry")
    data += struct.pack("<BihiB", 0, 1, 0, 0, 0)
    data += struct.pack("<H", 1)
    data += _text("Value")
    data += struct.pack("<i", 6) + _blob16(b"\x07")
    data += struct.pack("<iBi", 0, 0, 0)

    data += struct.pack("<H", 1)
    data += _text("Run")
    data += struct.pack("<iBBB", 0x16, 0, 0, 0)
    data += _blob16(b"\x00")
    data += struct.pack("<B", 1) + _blob16(b"\x0C")
    data += struct.pack("<BHH", 1, 8, 1)
    data += struct.pack("<B", 0) + _blob16(b"\x07")
    il = b"\x72\0\0\0\0\x26\x2A"
    data += struct.pack("<i", len(il)) + il
    effective_fixup_offset = 1 if fixup_offset is None else fixup_offset
    data += (
        struct.pack("<HiB", 1, effective_fixup_offset, 3)
        + _blob16(_text("hello"))
    )
    data += struct.pack("<H", 0)
    return bytes(data)


def test_reports_complete_managed_structure_without_loading_clr() -> None:
    report = inspect_managed_handoff_image(_fixture())

    assert report["status"] == "parsed"
    assert report["namespace"] == "Fixture"
    assert report["main_class"] == "Entry"
    assert report["type_count"] == 1
    assert report["field_count"] == 1
    assert report["method_count"] == 1
    assert report["il_bytes"] == 7
    assert report["fixup_kind_counts"] == {"3": 1}
    assert report["string_literals"] == ["hello"]
    assert report["data_blobs"][0]["size"] == 4
    assert report["complete_input_consumed"] is True
    assert report["executed"] is False
    assert report["emulated"] is False
    assert report["clr_loaded"] is False


def test_rejects_truncation_and_trailing_data() -> None:
    truncated = inspect_managed_handoff_image(_fixture()[:-1])
    trailing = inspect_managed_handoff_image(_fixture() + b"extra")

    assert truncated["status"] == "invalid_structure"
    assert truncated["reason"].endswith("_truncated")
    assert trailing["status"] == "invalid_structure"
    assert trailing["reason"] == "trailing_data"


def test_rejects_fixup_outside_method_il() -> None:
    report = inspect_managed_handoff_image(_fixture(fixup_offset=7))

    assert report["status"] == "invalid_structure"
    assert report["reason"] == "fixup_offset_out_of_bounds"


def test_rejects_unknown_version_without_parsing_body() -> None:
    report = inspect_managed_handoff_image(_fixture(version=2))

    assert report["status"] == "unsupported_version"
    assert report["version"] == 2
