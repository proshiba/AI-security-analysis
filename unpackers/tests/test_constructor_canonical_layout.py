"""小さい人工PEでparser補正不要の配置だけを構築前に受理する。検体・IL実行なし。"""
import struct

import dnfile
import pytest

from unpackers.tests import test_constructor_declarations_portable as fixture

guard = fixture.guard
insert = fixture.constructor_insert


def _word(data, offset, value):
    return insert(data, offset, value.to_bytes(4, "little"))


def _misaligned_two_row_pe():
    low = fixture.constructor_build_pe()
    alternate = fixture.constructor_build_pe({6: 2})
    low_size = int.from_bytes(low[0x20C:0x210], "little")
    alternate_size = int.from_bytes(alternate[0x20C:0x210], "little")
    assert alternate_size < 0x80
    data = low + bytes(0x800 - len(low))
    for offset, content in (
        (0x178 + 8, (0x400).to_bytes(4, "little")),
        (0x178 + 16, (0x400).to_bytes(4, "little")),
        (0x178 + 20, (0x280).to_bytes(4, "little")),
        (0x200, alternate[0x200:0x248]),
        (0x280, low[0x200:0x248]),
        (0x300, alternate[0x300:0x300 + alternate_size]),
        (0x380, low[0x300:0x300 + low_size]),
    ):
        data = insert(data, offset, content)
    return data


def test_preconstructor_rejects_two_row_offset_divergence(monkeypatch):
    data = _misaligned_two_row_pe()
    result = guard.preflight_clr_declarations(data, max_table_rows=1)
    assert result["reason_counts"] == {"preflight_section_layout_unsupported": 1}
    for module, analyze in ((fixture.triage, fixture.triage.analyze_managed_pe),
                            (fixture.proxy, fixture.proxy.analyze_managed_protector)):
        calls = fixture.constructor_factory_counter(monkeypatch, module)
        output = analyze(data)
        assert calls == []
        assert not output["metadata_preflight"]["accepted"]
    # bypassした小さい2行parser解釈は旧不一致の対照証明のみ。巨大rowを宣言/割当しない。
    pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    try:
        assert pe.net.mdtables.MethodDef.num_rows == len(pe.net.mdtables.MethodDef.rows) == 2
    finally:
        pe.close()


@pytest.mark.parametrize("value", [0, 1, 0x100, 0x300, 0x20000])
def test_noncanonical_file_alignment_is_partial(value):
    data = _word(fixture.constructor_build_pe(), 0x98 + 36, value)
    assert guard.preflight_clr_declarations(data)["reason_counts"] == {"preflight_pe_layout_unsupported": 1}


@pytest.mark.parametrize("value", [0, 0x200, 0x300, 0x800, 0x1800])
def test_low_or_nonpower_section_alignment_is_unsupported(value):
    data = _word(fixture.constructor_build_pe(), 0x98 + 32, value)
    assert guard.preflight_clr_declarations(data)["reason_counts"] == {"preflight_pe_layout_unsupported": 1}


def test_section_alignment_smaller_than_file_alignment_is_partial():
    data = _word(fixture.constructor_build_pe(), 0x98 + 36, 0x4000)
    assert guard.preflight_clr_declarations(data)["reason_counts"] == {"preflight_pe_layout_unsupported": 1}


@pytest.mark.parametrize("value", [0, 0x180, 0x201, 0x1000])
def test_headers_extent_must_cover_table_and_be_bounded_aligned(value):
    data = _word(fixture.constructor_build_pe(), 0x98 + 60, value)
    assert guard.preflight_clr_declarations(data)["reason_counts"] == {"preflight_pe_layout_unsupported": 1}


@pytest.mark.parametrize("field,value", [(12, 0x2001), (20, 0x280), (20, 0)])
def test_raw_adjustment_or_header_alias_is_unsupported(field, value):
    # raw終端の破損を混ぜず、alignment/header配置の理由だけを点検する。
    data = _word(fixture.constructor_build_pe() + bytes(0x200), 0x178 + field, value)
    assert guard.preflight_clr_declarations(data)["reason_counts"] == {"preflight_section_layout_unsupported": 1}


def test_size_of_headers_cannot_extend_into_section_bytes():
    data = _word(fixture.constructor_build_pe(), 0x98 + 60, 0x400)
    assert guard.preflight_clr_declarations(data)["reason_counts"] == {"preflight_section_layout_unsupported": 1}


def test_virtual_extent_overflow_is_unsupported():
    data = fixture.constructor_build_pe()
    data = _word(data, 0x178 + 12, 0xFFFFF000)
    data = _word(data, 0x178 + 8, 0x2000)
    assert guard.preflight_clr_declarations(data)["reason_counts"] == {"preflight_section_layout_unsupported": 1}


def _two_section_pe(*, first_virtual=0x1000, second_rva=0x3000, second_raw=0x200, second_offset=0x400):
    data = fixture.constructor_build_pe() + bytes(0x200)
    data = insert(data, 0x80 + 6, (2).to_bytes(2, "little"))
    data = _word(data, 0x178 + 8, first_virtual)
    second = struct.pack("<8sIIIIIIHHI", b".second", 0x1000, second_rva,
                         second_raw, second_offset, 0, 0, 0, 0, 0x40000040)
    return insert(data, 0x178 + 40, second)


@pytest.mark.parametrize("first_virtual,second_rva,second_raw,second_offset", [
    (0x2000, 0x3000, 0x200, 0x400),
    (0x200, 0x2000, 0, 0),
    (0x1000, 0x3000, 0x200, 0x200),
])
def test_virtual_tail_alias_zero_raw_alias_and_raw_file_alias_are_partial(first_virtual, second_rva, second_raw, second_offset):
    data = _two_section_pe(first_virtual=first_virtual, second_rva=second_rva,
                           second_raw=second_raw, second_offset=second_offset)
    assert guard.preflight_clr_declarations(data)["reason_counts"] == {"preflight_section_layout_unsupported": 1}


@pytest.mark.parametrize("second_raw,second_offset", [(0x200, 0x400), (0, 0)])
def test_touching_virtual_spans_and_disjoint_bss_do_not_false_reject(second_raw, second_offset):
    data = _two_section_pe(second_raw=second_raw, second_offset=second_offset)
    assert guard.preflight_clr_declarations(data)["accepted"]
    pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    try:
        assert fixture.binding.verify_pe_clr_input(data, pe)
        assert pe.get_offset_from_rva(0x2000) == 0x200
        assert pe.get_offset_from_rva(0x2100) == 0x300
    finally:
        pe.close()


@pytest.mark.parametrize("alignment", [0x200, 0x400, 0x10000])
def test_canonical_alignment_boundaries_map_to_same_raw_bytes(alignment):
    original = fixture.constructor_build_pe()
    metadata_size = int.from_bytes(original[0x20C:0x210], "little")
    section_alignment = max(0x1000, alignment)
    data = original + bytes(2 * alignment - len(original)) if 2 * alignment >= len(original) else original
    data = _word(data, 0x98 + 32, section_alignment)
    data = _word(data, 0x98 + 36, alignment)
    data = _word(data, 0x98 + 60, alignment)
    data = _word(data, 0x178 + 8, alignment)
    data = _word(data, 0x178 + 12, section_alignment)
    data = _word(data, 0x178 + 16, alignment)
    data = _word(data, 0x178 + 20, alignment)
    data = _word(data, 0x98 + 96 + 14 * 8, section_alignment)
    cli = original[0x200:0x248]
    cli = insert(cli, 8, (section_alignment + 0x100).to_bytes(4, "little"))
    data = insert(data, alignment, cli)
    data = insert(data, alignment + 0x100, original[0x300:0x300 + metadata_size])
    result = guard.preflight_clr_declarations(data)
    assert result["accepted"] and result["counts"]["rows_declared"] == 0
    pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    try:
        assert fixture.binding.verify_pe_clr_input(data, pe)
        assert pe.get_offset_from_rva(section_alignment) == alignment
        assert pe.get_offset_from_rva(section_alignment + 0x100) == alignment + 0x100
    finally:
        pe.close()
