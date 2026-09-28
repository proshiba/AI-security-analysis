"""最大2行の人工PEだけで、受理時のraw区間と実parserの写像を対照する。"""
import struct

import dnfile
import pytest

from unpackers.tests import test_constructor_declarations_portable as fixture
insert = fixture.constructor_insert


def _u32(data, offset, value):
    return insert(data, offset, value.to_bytes(4, "little"))


def _plus(data):
    raw_size = int.from_bytes(data[0x178 + 16:0x178 + 20], "little")
    optional = struct.pack("<HBB5IQII6H4I2H4QII", 0x20B, 0, 0,
                           0, raw_size, 0, 0, 0x2000, 0x140000000, 0x1000, 0x200,
                           4, 0, 0, 0, 4, 0, 0, 0x3000, 0x200, 0, 3, 0,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    assert len(optional) == 112
    optional += bytes(14 * 8) + struct.pack("<II", 0x2000, 72) + bytes(8)
    section = data[0x178:0x178 + 40]
    data = insert(data, 0x80 + 4, (0x8664).to_bytes(2, "little"))
    data = insert(data, 0x80 + 20, len(optional).to_bytes(2, "little"))
    data = insert(data, 0x98, optional)
    return insert(data, 0x188, section)


def _bss(data, *, empty=False, reverse=False):
    data = insert(data, 0x80 + 6, (2).to_bytes(2, "little"))
    first = data[0x178:0x178 + 40]
    second = struct.pack("<8sIIIIIIHHI", b".bss", 0 if empty else 0x1000, 0x3000,
                         0, 0, 0, 0, 0, 0, 0x40000080)
    return insert(data, 0x178, second + first if reverse else first + second)


def _mutate(data, variant):
    if variant == "small_virtual":
        return _u32(data, 0x178 + 8, 1)
    if variant == "odd_raw_size":
        return _u32(data, 0x178 + 16, 0x1FF)
    if variant == "empty_bss":
        return _bss(data, empty=True)
    if variant == "bss":
        return _bss(data)
    if variant == "reversed_bss":
        return _bss(data, reverse=True)
    if variant == "reversed_bss_small_virtual":
        return _u32(_bss(data, reverse=True), 0x178 + 40 + 8, 1)
    if variant == "misaligned_raw":
        return _u32(data + bytes(0x200), 0x178 + 20, 0x280)
    if variant == "low_alignment":
        return _u32(data, 0x98 + 32, 0x200)
    if variant == "pe32plus":
        return _plus(data)
    if variant == "pe32plus_odd_raw_size":
        return _u32(_plus(data), 0x188 + 16, 0x1FF)
    assert variant == "baseline"
    return data


def _raw_sections_and_directory(data):
    optional = 0x98
    count = int.from_bytes(data[0x86:0x88], "little")
    optional_size = int.from_bytes(data[0x94:0x96], "little")
    start = optional + optional_size
    sections = tuple(tuple(int.from_bytes(data[start + 40 * index + field:start + 40 * index + field + 4], "little")
                           for field in (12, 16, 20)) for index in range(count))
    magic = int.from_bytes(data[optional:optional + 2], "little")
    directory = optional + (96 if magic == 0x10B else 112) + 14 * 8
    return sections, tuple(int.from_bytes(data[directory + field:directory + field + 4], "little") for field in (0, 4))


@pytest.mark.parametrize("rows", [0, 1, 2])
@pytest.mark.parametrize("variant", ["baseline", "small_virtual", "odd_raw_size", "empty_bss", "bss",
                                     "reversed_bss", "reversed_bss_small_virtual", "misaligned_raw", "low_alignment",
                                     "pe32plus", "pe32plus_odd_raw_size"])
def test_accepted_artificial_mapping_equals_parser_and_rejected_remains_partial(rows, variant):
    data = _mutate(fixture.constructor_build_pe({6: rows} if rows else None), variant)
    result = fixture.guard.preflight_clr_declarations(data)
    if variant in {"misaligned_raw", "low_alignment"}:
        assert not result["accepted"] and result["status"] == "partial"
        assert result["reason_counts"]
        return
    assert result["accepted"] and result["counts"]["rows_declared"] == rows
    sections, (clr_rva, clr_size) = _raw_sections_and_directory(data)
    clr = fixture.binding.unique_file_span(sections, clr_rva, clr_size)
    assert clr is not None
    metadata_rva = int.from_bytes(data[clr + 8:clr + 12], "little")
    metadata_size = int.from_bytes(data[clr + 12:clr + 16], "little")
    metadata = fixture.binding.unique_file_span(sections, metadata_rva, metadata_size)
    assert metadata is not None
    pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    try:
        assert pe.get_offset_from_rva(clr_rva) == clr
        assert pe.get_data(clr_rva, clr_size) == data[clr:clr + clr_size]
        assert pe.get_offset_from_rva(metadata_rva) == metadata
        assert pe.get_data(metadata_rva, metadata_size) == data[metadata:metadata + metadata_size]
        table = pe.net.mdtables.MethodDef
        assert (0 if table is None else table.num_rows) == rows <= 2
    finally:
        pe.close()
