"""PE import directory解析失敗時のunknown/partial契約を検証する。"""

from __future__ import annotations

from types import SimpleNamespace
import struct

import pytest

from unpackers import static_control_flow, static_unpacker


class FakeSection:
    def __init__(
        self,
        name: bytes,
        *,
        virtual_address: int,
        raw_offset: int,
        raw_size: int,
        virtual_size: int,
        characteristics: int,
        payload: bytes,
    ) -> None:
        self.Name = name.ljust(8, b"\0")
        self.VirtualAddress = virtual_address
        self.PointerToRawData = raw_offset
        self.SizeOfRawData = raw_size
        self.Misc_VirtualSize = virtual_size
        self.Characteristics = characteristics
        self._payload = payload

    def get_data(self) -> bytes:
        return self._payload


def _fake_image() -> SimpleNamespace:
    high_entropy = bytes(range(256)) * 16
    sections = [
        FakeSection(
            b".text",
            virtual_address=0x1000,
            raw_offset=0x200,
            raw_size=len(high_entropy),
            virtual_size=len(high_entropy),
            characteristics=0x60000020,
            payload=high_entropy,
        )
    ]
    sections.extend(
        FakeSection(
            f".z{index}".encode(),
            virtual_address=0x3000 + index * 0x1000,
            raw_offset=0,
            raw_size=0,
            virtual_size=0x1000,
            characteristics=0xC0000040,
            payload=b"",
        )
        for index in range(4)
    )
    imports = [
        SimpleNamespace(
            dll=b"KERNEL32.dll",
            imports=[SimpleNamespace(name=b"VirtualAlloc", address=0x401000)],
        )
    ]
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(16)]
    image = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(
            AddressOfEntryPoint=0x1000,
            SizeOfHeaders=0x200,
            ImageBase=0x400000,
            DATA_DIRECTORY=directories,
        ),
        sections=sections,
        DIRECTORY_ENTRY_IMPORT=imports,
        get_overlay_data_start_offset=lambda: None,
    )

    def broken_directory_parse(*, directories) -> None:  # noqa: ANN001
        if directories == [
            static_unpacker.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ]:
            raise struct.error("malformed import directory")

    image.parse_data_directories = broken_directory_parse
    return image


def test_control_flow_treats_failed_import_parse_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stale empty/import属性を信頼せずlow-import VM heuristicを無効化する。"""

    image = _fake_image()
    monkeypatch.setattr(static_control_flow.pefile, "PE", lambda **_kwargs: image)

    def capture_context(
        _data,
        _mappings,
        _entrypoint,
        _bits,
        context,
        *_args,
        **_kwargs,
    ):
        return {"status": "analyzed", "static_context": context}

    monkeypatch.setattr(static_control_flow, "_analyze_mapped_code", capture_context)
    result = static_control_flow.analyze_pe_control_flow(b"MZ" + b"\0" * 8190)
    context = result["static_context"]

    assert context["import_directory_parse"]["status"] == "parse_failed"
    assert context["imports"] is None
    assert context["import_thunk_count"] is None
    assert context["virtualized_shape"] is False
    assert result["analysis_coverage"] == {
        "status": "partial",
        "imports_known": False,
        "low_import_heuristics_applied": False,
        "limitations": ["import_directory_parse_failed"],
    }


def test_unpacker_disables_import_dependent_packing_heuristics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """import parse失敗を0件と誤認してsuspected_packedへ分類しない。"""

    image = _fake_image()
    monkeypatch.setattr(static_unpacker.pefile, "PE", lambda **_kwargs: image)
    summary, artifacts = static_unpacker.pe_summary(b"MZ" + bytes(range(256)) * 31)

    assert artifacts == []
    assert summary["directory_parse"]["imports"]["status"] == "parse_failed"
    assert summary["imports"] is None
    assert summary["import_libraries"] is None
    assert summary["virtualized_shape"] is False
    assert summary["encrypted_sideload_host_shape"] is False
    assert summary["classification"] == "not_packed"
    assert summary["analysis_coverage"] == {
        "status": "partial",
        "imports_known": False,
        "low_import_heuristics_applied": False,
        "resources_complete": True,
        "limitations": ["import_directory_parse_failed"],
    }
