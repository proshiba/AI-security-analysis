from __future__ import annotations

from types import SimpleNamespace

import pytest

from unpackers import memory_pe_rebuilder as rebuilder


def _fake_pe(*, virtual_address: int = 0x1000, raw_size: int = 0x200):
    section = SimpleNamespace(
        Name=b".text\0\0\0",
        PointerToRawData=0x200,
        SizeOfRawData=raw_size,
        VirtualAddress=virtual_address,
    )
    return SimpleNamespace(
        FILE_HEADER=SimpleNamespace(NumberOfSections=1, Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(
            SizeOfImage=0x3000,
            SizeOfHeaders=0x200,
            AddressOfEntryPoint=0x1010,
        ),
        sections=[section],
    )


def test_rebuilds_rva_sections_into_file_layout(monkeypatch: pytest.MonkeyPatch) -> None:
    image = bytearray(0x3000)
    image[:2] = b"MZ"
    image[0x1000:0x1200] = b"A" * 0x200
    fake = _fake_pe()
    monkeypatch.setattr(rebuilder.pefile, "PE", lambda **_kwargs: fake)

    report, output = rebuilder.rebuild_memory_pe(bytes(image))

    assert output[:2] == b"MZ"
    assert output[0x200:0x400] == b"A" * 0x200
    assert report["status"] == "rebuilt"
    assert report["output_size"] == 0x400
    assert report["executed"] is False


def test_rejects_section_outside_memory_image(monkeypatch: pytest.MonkeyPatch) -> None:
    image = bytearray(0x3000)
    image[:2] = b"MZ"
    fake = _fake_pe(virtual_address=0x2F00, raw_size=0x200)
    monkeypatch.setattr(rebuilder.pefile, "PE", lambda **_kwargs: fake)

    with pytest.raises(rebuilder.MemoryPEError, match="section RVA"):
        rebuilder.rebuild_memory_pe(bytes(image))


def test_rejects_non_pe_prefix() -> None:
    with pytest.raises(rebuilder.MemoryPEError, match="MZ header"):
        rebuilder.rebuild_memory_pe(b"not a memory PE")
